//! `log`: the daemon's audit log.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use credential_bridge_config::DaemonConfig;

use super::{Context, daemon_config, daemon_paths, load_config, printable};
use crate::cli::LogArgs;

/// How often `log -f` looks for new lines.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(500);

/// `log`: reads the audit log file, formats events (or raw JSON), follows with `-f`.
pub fn log(ctx: &Context, args: &LogArgs) -> anyhow::Result<()> {
    let config = load_config(ctx).ok();
    let path = audit_log(&daemon_config(ctx, config.as_ref()));
    let print = |line: &str| println!("{}", if args.json { printable(line) } else { format_event(line) });

    let file = match File::open(&path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && args.follow => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("no audit log yet at {}", path.display());
            return Ok(());
        }
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut position = 0;
    if let Some(file) = file {
        let mut last = VecDeque::with_capacity(args.lines.min(10_000));
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if !line.ends_with('\n') {
                break; // an incomplete last line is read again when following
            }
            position += line.len() as u64;
            if args.lines > 0 {
                if last.len() == args.lines {
                    last.pop_front();
                }
                last.push_back(line.trim_end().to_owned());
            }
            line.clear();
        }
        last.iter().for_each(|line| print(line));
    }
    if args.follow {
        follow(&path, position, print)?;
    }
    Ok(())
}

/// The audit log the running daemon writes, else the configured one.
pub(crate) fn audit_log(daemon: &DaemonConfig) -> PathBuf {
    daemon_paths(daemon).map_or_else(|_| daemon.audit_log.clone(), |paths| PathBuf::from(paths.audit_log))
}

/// Prints complete lines appended after `position`, forever. Starts over when the file
/// is replaced (rotation) or truncated.
fn follow(path: &Path, mut position: u64, print: impl Fn(&str)) -> anyhow::Result<()> {
    let mut inode = std::fs::metadata(path).map(|meta| meta.ino()).ok();
    let mut pending = Vec::new();
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        let Ok(meta) = std::fs::metadata(path) else { continue };
        if Some(meta.ino()) != inode || meta.len() < position {
            inode = Some(meta.ino());
            position = 0;
            pending.clear();
        }
        if meta.len() == position {
            continue;
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(position))?;
        let mut chunk = Vec::new();
        file.take(meta.len() - position).read_to_end(&mut chunk)?;
        position += chunk.len() as u64;
        pending.extend_from_slice(&chunk);
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            print(String::from_utf8_lossy(&line).trim_end());
        }
    }
}

/// One audit line for people: `time event key=value …`. Lines that are not JSON objects
/// are shown as they are. Control characters are removed either way, since some values
/// (git targets, names) come from servers.
pub fn format_event(line: &str) -> String {
    let Ok(serde_json::Value::Object(mut fields)) = serde_json::from_str::<serde_json::Value>(line) else {
        return printable(line);
    };
    let text = |value: &serde_json::Value| match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let time = fields.remove("time").map(|value| text(&value)).unwrap_or_default();
    let event = fields.remove("event").map(|value| text(&value)).unwrap_or_default();
    let mut out = format!("{time} {event:<8}");
    for (key, value) in &fields {
        if value.is_null() {
            continue;
        }
        let value = text(value);
        if value.contains(char::is_whitespace) || value.is_empty() {
            out.push_str(&format!(" {key}=\"{}\"", value.replace('"', "\\\"")));
        } else {
            out.push_str(&format!(" {key}={value}"));
        }
    }
    printable(out.trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_audit_events() {
        let line = r#"{"time":"2026-11-20T10:00:00Z","event":"git","server":"buildserver","target":"github.com/my-org/app.git","rule":null,"outcome":"no match"}"#;
        assert_eq!(
            format_event(line),
            "2026-11-20T10:00:00Z git      outcome=\"no match\" server=buildserver target=github.com/my-org/app.git"
        );
        assert_eq!(format_event("not json"), "not json");
        assert_eq!(
            format_event(r#"{"event":"hop","host_key":"ssh-ed25519 SHA256:x\u001b[2J"}"#),
            "hop      host_key=\"ssh-ed25519 SHA256:x?[2J\""
        );
    }

    /// The running daemon's audit log wins over the configured one.
    #[test]
    fn reads_the_log_of_the_running_daemon() {
        let (dir, ctx) = crate::commands::test_support::context();
        let daemon = DaemonConfig::from_paths(&ctx.paths);
        assert_eq!(audit_log(&daemon), daemon.audit_log);
        let elsewhere = dir.path().join("elsewhere.log");
        let paths = credential_bridge_proto::ipc::control::DaemonPaths {
            audit_log: elsewhere.display().to_string(),
            ..Default::default()
        };
        let pong = credential_bridge_proto::ipc::control::Response::Pong {
            version: crate::commands::VERSION.into(),
            paths,
        };
        crate::commands::test_support::fake_daemon(&daemon.control_socket, pong);
        assert_eq!(audit_log(&daemon), elsewhere);
    }

    #[test]
    fn reads_the_last_lines() {
        let (_dir, mut ctx) = crate::commands::test_support::context();
        let log_path = ctx.paths.audit_log.clone();
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        std::fs::write(&log_path, "{\"event\":\"a\"}\n{\"event\":\"b\"}\n").unwrap();
        ctx.config_path = ctx.paths.home.join("none.toml");
        log(&ctx, &LogArgs { follow: false, lines: 1, json: false }).unwrap();
        std::fs::remove_file(&log_path).unwrap();
        log(&ctx, &LogArgs { follow: false, lines: 1, json: true }).unwrap();
    }
}
