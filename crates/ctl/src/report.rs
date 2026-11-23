//! Report lines as in the `server add` example of `docs/architecture.md`:
//!
//! ```text
//! ✓ known_hosts          buildserver: ssh-ed25519, ssh-rsa (followed)
//! ⚠ ssh config           no ForwardAgent to the proxy for buildserver
//!                        → credential-bridge-ctl server ssh-config buildserver
//! ```

use std::fmt;

/// Outcome of one step or check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `✓`
    Ok,
    /// `⚠`: works, but something should be done.
    Warn,
    /// `✗`: does not work.
    Fail,
}

impl Status {
    /// The symbol.
    pub fn symbol(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Warn => "⚠",
            Status::Fail => "✗",
        }
    }
}

/// One report line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The outcome.
    pub status: Status,
    /// Left column, e.g. `known_hosts`.
    pub label: String,
    /// Right column.
    pub detail: String,
    /// A command or hint on the next line, prefixed with `→`.
    pub hint: Option<String>,
}

impl Line {
    /// A line without hint.
    pub fn new(status: Status, label: impl Into<String>, detail: impl Into<String>) -> Line {
        Line { status, label: label.into(), detail: detail.into(), hint: None }
    }

    /// A `✓` line.
    pub fn ok(label: impl Into<String>, detail: impl Into<String>) -> Line {
        Line::new(Status::Ok, label, detail)
    }

    /// A `⚠` line.
    pub fn warn(label: impl Into<String>, detail: impl Into<String>) -> Line {
        Line::new(Status::Warn, label, detail)
    }

    /// A `✗` line.
    pub fn fail(label: impl Into<String>, detail: impl Into<String>) -> Line {
        Line::new(Status::Fail, label, detail)
    }

    /// Adds a hint shown on the next line.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Line {
        self.hint = Some(hint.into());
        self
    }
}

/// Lines printed as they are added; remembers whether any failed.
#[derive(Debug, Default)]
pub struct Report {
    /// Every line so far.
    pub lines: Vec<Line>,
    /// Print each line when it is added.
    pub print: bool,
    /// Everything shown so far: the lines and other text (tables, diffs), in order.
    pub text: String,
}

impl Report {
    /// A report that prints each line to stdout as it is added.
    pub fn printing() -> Report {
        Report { print: true, ..Report::default() }
    }

    /// Adds (and prints) a line.
    pub fn push(&mut self, line: Line) {
        let text = format!("{line}\n");
        self.show(&text);
        self.lines.push(line);
    }

    /// Shows other text (a table, a diff) as it is.
    pub fn show(&mut self, text: &str) {
        if self.print {
            use std::io::Write as _;
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
        }
        self.text.push_str(text);
    }

    /// Whether any line has [`Status::Fail`].
    pub fn failed(&self) -> bool {
        self.lines.iter().any(|line| line.status == Status::Fail)
    }
}

/// Width of the label column.
pub const LABEL_WIDTH: usize = 20;

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:<LABEL_WIDTH$} {}", self.status.symbol(), self.label, self.detail)?;
        if let Some(hint) = &self.hint {
            for (index, hint_line) in hint.lines().enumerate() {
                let arrow = if index == 0 { "→" } else { " " };
                write!(f, "\n  {:<LABEL_WIDTH$} {arrow} {hint_line}", "")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_the_design() {
        let line = Line {
            status: Status::Warn,
            label: "ssh config".into(),
            detail: "no ForwardAgent to the proxy for buildserver".into(),
            hint: Some("credential-bridge-ctl server ssh-config buildserver".into()),
        };
        assert_eq!(
            line.to_string(),
            "⚠ ssh config           no ForwardAgent to the proxy for buildserver\n                       → credential-bridge-ctl server ssh-config buildserver"
        );
    }

    #[test]
    fn report_remembers_failures() {
        let mut report = Report::default();
        report.push(Line::ok("daemon", "running"));
        report.push(Line::warn("ssh config", "x").with_hint("a\nb"));
        assert!(!report.failed());
        assert_eq!(
            report.lines[1].to_string(),
            format!("⚠ {:<20} x\n  {:<20} → a\n  {:<20}   b", "ssh config", "", "")
        );
        report.push(Line::fail("vault", "missing"));
        assert!(report.failed());
    }
}
