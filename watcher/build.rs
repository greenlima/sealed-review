const SAVED_BUNDLE: &str = "tests/fixtures/bundle-3.json";

/// Enables the tests on a recorded NEAR bundle where that bundle exists; the public repository has none.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(saved_bundle)");
    if std::path::Path::new(SAVED_BUNDLE).exists() {
        println!("cargo::rerun-if-changed={SAVED_BUNDLE}");
        println!("cargo::rustc-cfg=saved_bundle");
    } else {
        println!("cargo::rerun-if-changed=build.rs");
    }
}
