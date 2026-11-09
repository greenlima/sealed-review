//! How `ask` reads on a terminal: colour only when stderr is one and `NO_COLOR` is unset.

use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::feed::OpenCheck;
use crate::gate::{Pass, scope_name};
use crate::verdict::{Status, Tier};

const GREEN: &str = "1;92";
const YELLOW: &str = "1;93";
const RED: &str = "1;91";
const MAGENTA: &str = "1;95";
const CYAN: &str = "36";
const DIM: &str = "2";
const BOLD: &str = "1";
const WIDEST: usize = 120;
const NARROWEST_REASON: usize = 24;
const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const HEADINGS: [&str; 4] = ["status", "machine", "check", "reason"];

#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
    live: bool,
    width: usize,
}

/// Animates a line on stderr until dropped, then clears it.
pub struct Spinner {
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Style {
    pub fn stderr() -> Self {
        let live = std::io::stderr().is_terminal();
        let width = terminal_size::terminal_size_of(std::io::stderr())
            .map_or(100, |(w, _)| usize::from(w.0));
        Self {
            color: live && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
            live,
            width: width.min(WIDEST),
        }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn tier(self, tier: Tier) -> String {
        let (code, name) = match tier {
            Tier::Affirming => (GREEN, "affirming"),
            Tier::Warning => (YELLOW, "warning"),
            Tier::Contraindicated => (RED, "contraindicated"),
            Tier::None => (MAGENTA, "none"),
        };
        self.paint(code, name)
    }

    fn ok(self) -> String {
        self.paint(GREEN, "✓")
    }

    /// Shows `label` with a spinner and the seconds waited, on a terminal only.
    pub fn spin(self, label: &str) -> Spinner {
        let done = Arc::new(AtomicBool::new(false));
        let thread = self.live.then(|| {
            let done = Arc::clone(&done);
            let label = label.to_owned();
            std::thread::spawn(move || {
                let start = Instant::now();
                for frame in FRAMES.iter().cycle() {
                    if done.load(Ordering::Relaxed) {
                        break;
                    }
                    let spent = start.elapsed().as_secs_f32();
                    let frame = self.paint(CYAN, &frame.to_string());
                    eprint!(
                        "\r\x1b[2K{frame} {label} {}",
                        self.paint(DIM, &format!("{spent:.1} s"))
                    );
                    std::thread::sleep(Duration::from_millis(80));
                }
                eprint!("\r\x1b[2K");
            })
        });
        Spinner { done, thread }
    }

    /// The gate's verdict, then a table of the checks it did not pass.
    pub fn passed(self, pass: &Pass) -> String {
        let machines = pass.tls_keys.len();
        let gate = format!(
            "{} {}  entry {} · {} · {machines} reviewed machine{}\n",
            self.ok(),
            self.paint(BOLD, "gate passed"),
            pass.seq,
            self.tier(pass.status),
            plural(machines)
        );
        if pass.open.is_empty() {
            return gate;
        }
        let count = pass.open.len();
        let intro = self.paint(
            DIM,
            &format!(
                "  {count} check{} did not pass; each is explained in METHOD.md\n",
                plural(count)
            ),
        );
        format!("{gate}{intro}{}", self.table(&pass.open))
    }

    fn table(self, open: &[OpenCheck]) -> String {
        let rows: Vec<[String; 3]> = open
            .iter()
            .map(|c| {
                [
                    label(c.status).to_owned(),
                    scope_name(&c.scope),
                    c.id.clone(),
                ]
            })
            .collect();
        let fixed: [usize; 3] = std::array::from_fn(|i| {
            rows.iter()
                .map(|r| r[i].chars().count())
                .chain([HEADINGS[i].chars().count()])
                .max()
                .unwrap_or_default()
        });
        let borders = 3 * HEADINGS.len() + 1;
        let reason = self
            .width
            .saturating_sub(fixed.iter().sum::<usize>() + borders)
            .max(NARROWEST_REASON);
        let widths = [fixed[0], fixed[1], fixed[2], reason];
        let line = |left: &str, mid: &str, right: &str| {
            let cells: Vec<String> = widths.iter().map(|w| "─".repeat(w + 2)).collect();
            format!(
                "{}\n",
                self.paint(DIM, &format!("{left}{}{right}", cells.join(mid)))
            )
        };
        let bar = self.paint(DIM, "│");
        let row = |cells: [String; 4]| {
            let inner: Vec<String> = cells.into_iter().map(|c| format!(" {c} ")).collect();
            format!("{bar}{}{bar}\n", inner.join(&bar))
        };
        let heading = row(std::array::from_fn(|i| {
            self.paint(BOLD, &pad(HEADINGS[i], widths[i]))
        }));
        let body: Vec<String> = open
            .iter()
            .zip(&rows)
            .map(|(check, cells)| {
                let code = colour(check.status);
                wrap(&check.detail, reason)
                    .iter()
                    .enumerate()
                    .map(|(i, text)| {
                        let first = i == 0;
                        let shown = |s: &str| if first { s.to_owned() } else { String::new() };
                        row([
                            self.paint(code, &pad(&shown(&cells[0]), widths[0])),
                            pad(&shown(&cells[1]), widths[1]),
                            self.paint(code, &pad(&shown(&cells[2]), widths[2])),
                            pad(text, reason),
                        ])
                    })
                    .collect()
            })
            .collect();
        format!(
            "{}{heading}{}{}{}",
            line("┌", "┬", "┐"),
            line("├", "┼", "┤"),
            body.join(&line("├", "┼", "┤")),
            line("└", "┴", "┘")
        )
    }

    /// The server key the answer came over and, through the gateway, the model key it was sealed to.
    pub fn served(self, tls_key: &str, model_key: Option<&str>) -> String {
        let mut out = format!(
            "{} answered on the connection with TLS key {}\n",
            self.ok(),
            self.paint(CYAN, tls_key)
        );
        if let Some(key) = model_key {
            out.push_str(&format!(
                "{} end-to-end encrypted to model key {}\n",
                self.ok(),
                self.paint(CYAN, key)
            ));
        }
        out
    }

    /// The rule above the model's answer, naming the model.
    pub fn opening(self, model: &str) -> String {
        let title = format!("─── {model} ");
        let fill = "─".repeat(self.width.saturating_sub(title.chars().count()));
        self.paint(MAGENTA, &format!("{title}{fill}"))
    }

    pub fn closing(self) -> String {
        self.paint(MAGENTA, &"─".repeat(self.width))
    }

    pub fn refused(self, error: &anyhow::Error) -> String {
        format!("{} {error:#}", self.paint(RED, "✗"))
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn label(status: Status) -> &'static str {
    match status {
        Status::Pass => "✓ pass",
        Status::Warn => "▲ warn",
        Status::Fail => "✗ fail",
        Status::Unknown => "? unknown",
    }
}

fn colour(status: Status) -> &'static str {
    match status {
        Status::Pass => GREEN,
        Status::Warn => YELLOW,
        Status::Fail => RED,
        Status::Unknown => MAGENTA,
    }
}

fn pad(text: &str, width: usize) -> String {
    format!("{text:<width$}")
}

/// Breaks `text` at spaces into lines of at most `width` characters; a longer word is cut.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let pieces = text.split_whitespace().flat_map(|word| {
        let chars: Vec<char> = word.chars().collect();
        chars
            .chunks(width)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
    });
    let mut lines = vec![String::new()];
    for piece in pieces {
        let Some(line) = lines.last_mut() else {
            continue;
        };
        let used = line.chars().count();
        if used == 0 {
            line.push_str(&piece);
        } else if used + 1 + piece.chars().count() <= width {
            line.push(' ');
            line.push_str(&piece);
        } else {
            lines.push(piece);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Style = Style {
        color: false,
        live: false,
        width: 82,
    };
    const COLOR: Style = Style {
        color: true,
        live: false,
        width: 72,
    };

    fn check(scope: &str, id: &str, detail: &str) -> OpenCheck {
        OpenCheck {
            scope: scope.into(),
            id: id.into(),
            status: Status::Warn,
            detail: detail.into(),
        }
    }

    fn warning() -> Pass {
        Pass {
            seq: 2,
            status: Tier::Warning,
            exp: 0,
            corrected_by: None,
            tls_keys: vec!["aa".into()],
            model_keys: Vec::new(),
            open: vec![
                check("route", "forwarding_observable", "not visible"),
                check(
                    "candidate/19aea1693533dc2d/aaf70a60",
                    "nvswitch",
                    "vm_config declares 4 NVSwitches and the report carries no switch evidence",
                ),
            ],
        }
    }

    #[test]
    fn open_checks_read_as_a_table() {
        let expected = "\
✓ gate passed  entry 2 · warning · 1 reviewed machine
  2 checks did not pass; each is explained in METHOD.md
┌────────┬────────────────────┬───────────────────────┬──────────────────────────┐
│ status │ machine            │ check                 │ reason                   │
├────────┼────────────────────┼───────────────────────┼──────────────────────────┤
│ ▲ warn │ route              │ forwarding_observable │ not visible              │
├────────┼────────────────────┼───────────────────────┼──────────────────────────┤
│ ▲ warn │ candidate 19aea169 │ nvswitch              │ vm_config declares 4     │
│        │                    │                       │ NVSwitches and the       │
│        │                    │                       │ report carries no switch │
│        │                    │                       │ evidence                 │
└────────┴────────────────────┴───────────────────────┴──────────────────────────┘
";
        assert_eq!(PLAIN.passed(&warning()), expected);
        let wide = Style {
            width: 100,
            ..PLAIN
        }
        .passed(&warning());
        assert!(wide.lines().all(|l| l.chars().count() <= 100), "{wide}");
        assert_eq!(wide.lines().nth(2).map(|l| l.chars().count()), Some(100));
    }

    #[test]
    fn long_words_are_cut_and_short_ones_kept() {
        assert_eq!(wrap("aaaaaaa bb c", 3), ["aaa", "aaa", "a", "bb", "c"]);
        assert_eq!(wrap("", 5), [""]);
    }

    #[test]
    fn colour_marks_the_tier_and_each_check() {
        let out = COLOR.passed(&warning());
        assert!(out.contains("\x1b[1;93mwarning\x1b[0m"), "{out}");
        assert!(
            out.contains("\x1b[1;93mforwarding_observable\x1b[0m"),
            "{out}"
        );
        assert!(!PLAIN.passed(&warning()).contains('\x1b'));
        assert_eq!(
            PLAIN.served("aa", Some("bb")),
            "✓ answered on the connection with TLS key aa\n\
             ✓ end-to-end encrypted to model key bb\n"
        );
        assert_eq!(PLAIN.opening("m").chars().count(), 82);
    }
}
