use std::path::Path;

use anyhow::{Context, Result, bail};
use dcap_qvl::quote::TDReport10;
use dstack_mr::{Machine, TdxMeasurements};
use dstack_types::{ImageInfo, VmConfig};
use sha2::{Digest, Sha256};

use crate::verdict::{Check, Status};

const MANIFEST: &str = "sha256sum.txt";

/// The image directory is the one `os_image_hash` names: its manifest hashes to it and every
/// listed file matches the manifest.
pub fn verify_image(dir: &Path, os_image_hash: &[u8]) -> Result<ImageInfo> {
    let manifest =
        std::fs::read(dir.join(MANIFEST)).with_context(|| format!("reading {MANIFEST}"))?;
    let identity = Sha256::digest(&manifest);
    if identity.as_slice() != os_image_hash {
        bail!(
            "sha256({MANIFEST}) = {}, vm_config declares {}",
            hex::encode(identity),
            hex::encode(os_image_hash)
        );
    }
    for line in std::str::from_utf8(&manifest)?
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let (want, name) = line
            .split_once("  ")
            .context("manifest line is not `<sha256>  <file>`")?;
        let have = Sha256::digest(
            std::fs::read(dir.join(name)).with_context(|| format!("reading {name}"))?,
        );
        if hex::encode(have) != want {
            bail!("{name} does not match the manifest");
        }
    }
    let metadata = std::fs::read_to_string(dir.join("metadata.json"))?;
    Ok(serde_json::from_str(&metadata)?)
}

/// MRTD and RTMR0–2 for this image on this VM shape, resolved as dstack's verifier does.
pub fn expected(dir: &Path, image: &ImageInfo, vm: &VmConfig) -> Result<TdxMeasurements> {
    let path = |file: &str| dir.join(file).display().to_string();
    let (firmware, kernel, initrd) = (path(&image.bios), path(&image.kernel), path(&image.initrd));
    let cmdline = dstack_mr::tdx::measured_kernel_cmdline(&image.cmdline);
    let ovmf_variant = vm.ovmf_variant.or(image.ovmf_variant).unwrap_or_default();

    Machine::builder()
        .cpu_count(vm.cpu_count)
        .memory_size(vm.memory_size)
        .firmware(&firmware)
        .kernel(&kernel)
        .initrd(&initrd)
        .kernel_cmdline(&cmdline)
        .root_verity(true)
        .hotplug_off(vm.hotplug_off)
        .maybe_two_pass_add_pages(vm.qemu_single_pass_add_pages)
        .normalized_setup_header(image.kernel_header_normalized)
        .maybe_pic(vm.pic)
        .maybe_qemu_version(vm.qemu_version.clone())
        .maybe_pci_hole64_size((vm.pci_hole64_size > 0).then_some(vm.pci_hole64_size))
        .hugepages(vm.hugepages)
        .numa_nodes(&vm.numa_nodes)
        .num_gpus(vm.num_gpus)
        .num_nics(vm.num_nics)
        .num_verity_volumes(vm.num_verity_volumes)
        .extra_root_devices(&vm.extra_root_devices)
        .swtpm(vm.swtpm)
        .num_nvswitches(vm.num_nvswitches)
        .host_share_mode(vm.host_share_mode.clone())
        .ovmf_variant(ovmf_variant)
        .build()
        .measure()
}

fn compare(expected: &TdxMeasurements, td: &TDReport10) -> Check {
    let pairs: [(&str, &[u8], &[u8]); 4] = [
        ("MRTD", &expected.mrtd, &td.mr_td),
        ("RTMR0", &expected.rtmr0, &td.rt_mr0),
        ("RTMR1", &expected.rtmr1, &td.rt_mr1),
        ("RTMR2", &expected.rtmr2, &td.rt_mr2),
    ];
    let differ: Vec<&str> = pairs
        .iter()
        .filter(|(_, e, q)| e != q)
        .map(|(n, _, _)| *n)
        .collect();
    let detail = if differ.is_empty() {
        "MRTD and RTMR0–2 recomputed by dstack-mr equal the quote".to_owned()
    } else {
        format!("recomputed values differ: [{}]", differ.join(", "))
    };
    Check::from_bool(3, "measurements", differ.is_empty(), detail)
}

/// Link 3: the declared OS image is the published one, and it is what booted on the declared VM shape.
pub fn checks(dir: Option<&Path>, vm: &VmConfig, td: &TDReport10) -> Vec<Check> {
    let Some(dir) = dir else {
        return vec![
            Check::new(
                3,
                "os_image",
                Status::Unknown,
                "image not in the cache (watcher image)",
            ),
            Check::new(
                3,
                "measurements",
                Status::Unknown,
                "image not in the cache (watcher image)",
            ),
        ];
    };
    let image = match verify_image(dir, &vm.os_image_hash) {
        Ok(image) => image,
        Err(e) => {
            return vec![
                Check::new(3, "os_image", Status::Fail, format!("{e:#}")),
                Check::new(3, "measurements", Status::Unknown, "image not verified"),
            ];
        }
    };
    let image_check = Check::new(
        3,
        "os_image",
        if image.is_dev {
            Status::Fail
        } else {
            Status::Pass
        },
        format!(
            "dstack OS {} (dev: {}), os_image_hash {}",
            image.version,
            image.is_dev,
            hex::encode(&vm.os_image_hash)
        ),
    );
    let measured = match expected(dir, &image, vm) {
        Ok(m) => compare(&m, td),
        Err(e) => Check::new(
            3,
            "measurements",
            Status::Unknown,
            format!("dstack-mr: {e:#}"),
        ),
    };
    vec![image_check, measured]
}
