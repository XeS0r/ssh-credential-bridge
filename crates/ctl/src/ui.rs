//! Terminal output: status symbols, colors and fix lines.
//!
//! Colors are used only on a terminal, never with `NO_COLOR` set or
//! `--color never`; the symbols stay in every case.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// `--color` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ColorChoice {
    /// Color when printing to a terminal and NO_COLOR is not set
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
struct Settings {
    color: bool,
    verbose: bool,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

pub fn init(choice: ColorChoice, verbose: bool) {
    let color = match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::io::stdout().is_terminal()
                && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
        }
    };
    let _ = SETTINGS.set(Settings { color, verbose });
}

fn settings() -> Settings {
    *SETTINGS.get_or_init(|| Settings { color: false, verbose: false })
}

pub fn verbose() -> bool {
    settings().verbose
}

fn paint(code: &str, text: &str) -> String {
    if settings().color { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
}

pub fn green(text: &str) -> String {
    paint("32", text)
}
pub fn yellow(text: &str) -> String {
    paint("33", text)
}
pub fn red(text: &str) -> String {
    paint("31", text)
}
pub fn cyan(text: &str) -> String {
    paint("36", text)
}
pub fn dim(text: &str) -> String {
    paint("2", text)
}
pub fn bold(text: &str) -> String {
    paint("1", text)
}

/// Severity of a check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    pub fn symbol(self) -> String {
        match self {
            Level::Ok => green("✓"),
            Level::Warn => yellow("⚠"),
            Level::Fail => red("✗"),
        }
    }

    /// A status dot in this level's color.
    pub fn dot(self) -> String {
        match self {
            Level::Ok => green("●"),
            Level::Warn => yellow("●"),
            Level::Fail => red("●"),
        }
    }
}

/// `→ <command>` under a problem, indented by `indent` spaces.
pub fn fix(indent: usize, command: &str) -> String {
    format!("{:indent$}{} {command}", "", dim("→"))
}

/// Replaces the home directory at the start of `path` with `~`.
pub fn tilde(path: &str, home: Option<&str>) -> String {
    match home.filter(|h| !h.is_empty()) {
        Some(home) => match path.strip_prefix(home.trim_end_matches('/')) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("~{rest}"),
            _ => path.to_owned(),
        },
        None => path.to_owned(),
    }
}

/// [`tilde`] with the local `$HOME`.
pub fn home_tilde(path: &std::path::Path) -> String {
    tilde(&path.to_string_lossy(), std::env::var("HOME").ok().as_deref())
}

/// `https://github.com/org/*` -> `github.com/org/*`; other protocols stay.
pub fn short_url(url: &str) -> &str {
    url.strip_prefix("https://").unwrap_or(url)
}

/// `1 problem`, `2 problems`.
pub fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Pads `text` to `width` columns, counting characters, not bytes; for text
/// that is colored afterwards.
pub fn pad(text: &str, width: usize) -> String {
    format!("{text}{}", " ".repeat(width.saturating_sub(text.chars().count())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_without_color() {
        assert_eq!(Level::Fail.symbol(), "✗");
        assert_eq!(fix(2, "do it"), "  → do it");
        assert_eq!(tilde("/home/me/.local/bin/x", Some("/home/me")), "~/.local/bin/x");
        assert_eq!(tilde("/home/me2/x", Some("/home/me")), "/home/me2/x");
        assert_eq!(tilde("/home/me", Some("/home/me/")), "~");
        assert_eq!(short_url("https://github.com/org/*"), "github.com/org/*");
        assert_eq!(short_url("http://x"), "http://x");
        assert_eq!(plural(1, "problem", "problems"), "1 problem");
        assert_eq!(pad("✓ ok", 6), "✓ ok  ");
    }
}
