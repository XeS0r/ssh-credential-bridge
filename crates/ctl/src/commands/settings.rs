//! `daemon set` and `gpg set|remove`: the single-table sections. `[vault.keepassxc]`
//! is written by `vault setup` and `vault forget` ([`super::vault`]).

use anyhow::bail;
use credential_bridge_config::edit::{DaemonKey, EditError};

use super::Context;
use super::change::{apply, apply_described, path_value, socket_value};
use crate::cli::{DaemonKeyArg, DaemonSetArgs, GpgSetArgs, WriteArgs};
use crate::report::Report;

/// `daemon set`. Like `vault setup`, it does not reload a running daemon: it reads these
/// settings when it starts, and [`apply`] says so.
pub fn daemon_set(ctx: &Context, args: &DaemonSetArgs, report: &mut Report) -> anyhow::Result<()> {
    let mut values: Vec<(DaemonKey, Option<String>)> = Vec::new();
    for (key, value) in [
        (DaemonKey::Socket, &args.socket),
        (DaemonKey::ForwardSocket, &args.forward_socket),
        (DaemonKey::ControlSocket, &args.control_socket),
        (DaemonKey::AuditLog, &args.audit_log),
    ] {
        if let Some(value) = value {
            values.push((key, Some(path_value(value)?)));
        }
    }
    for key in &args.unset {
        let key = match key {
            DaemonKeyArg::Socket => DaemonKey::Socket,
            DaemonKeyArg::ForwardSocket => DaemonKey::ForwardSocket,
            DaemonKeyArg::ControlSocket => DaemonKey::ControlSocket,
            DaemonKeyArg::AuditLog => DaemonKey::AuditLog,
        };
        if values.iter().any(|(set, _)| *set == key) {
            bail!("{} is both set and unset", key.name());
        }
        values.push((key, None));
    }
    if values.is_empty() {
        bail!(
            "nothing to set: give --socket, --forward-socket, --control-socket, --audit-log or --unset KEY"
        );
    }
    let names: Vec<&str> = values.iter().map(|(key, _)| key.name()).collect();
    let summary = format!("[daemon] {}", names.join(", "));
    apply(ctx, args.write.dry_run, report, &summary, |doc| {
        values.iter().try_for_each(|(key, value)| doc.set_daemon(*key, value.as_deref()))
    })?;
    Ok(())
}

/// `gpg set [--socket S | --unset-socket]`: creates `[gpg]` if missing; without an
/// option an existing `socket` stays.
pub fn gpg_set(ctx: &Context, args: &GpgSetArgs, report: &mut Report) -> anyhow::Result<()> {
    let socket = args.socket.as_deref().map(socket_value).transpose()?;
    let change: Option<Option<&str>> = match &socket {
        Some(socket) => Some(Some(socket)),
        None if args.unset_socket => Some(None),
        None => None,
    };
    apply_described(ctx, args.write.dry_run, report, |doc| {
        let existed = doc.contains(&["gpg"]);
        doc.set_gpg(change)?;
        // Without a change of the socket, an existing [gpg] stays as it is: `apply`
        // reports it unchanged and never shows this summary.
        Ok(match (existed, change) {
            (false, Some(Some(socket))) => format!("[gpg] added with socket = {socket}"),
            (false, _) => "[gpg] added".to_owned(),
            (true, Some(Some(socket))) => format!("[gpg] changed: socket = {socket}"),
            (true, _) => "[gpg] changed: socket removed (default gpgconf:agent-extra-socket)".to_owned(),
        })
    })?;
    Ok(())
}

/// `gpg remove`.
pub fn gpg_remove(ctx: &Context, args: &WriteArgs, report: &mut Report) -> anyhow::Result<()> {
    apply(ctx, args.dry_run, report, "[gpg] removed", |doc| {
        if doc.remove_gpg()? { Ok(()) } else { Err(EditError::NotFound { table: "[gpg]".to_owned() }) }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{context, write_config};

    const TEXT: &str = "version = 2   # schema\n\n[profile.dev]\nssh = { keys = \"all\" }\n";

    fn text(ctx: &Context) -> String {
        std::fs::read_to_string(&ctx.config_path).unwrap()
    }

    #[test]
    fn daemon_paths() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut args = DaemonSetArgs {
            socket: None,
            forward_socket: None,
            control_socket: None,
            audit_log: Some("~/logs/audit.log".into()),
            unset: Vec::new(),
            write: WriteArgs::default(),
        };
        let mut report = Report::default();
        daemon_set(&ctx, &args, &mut report).unwrap();
        assert!(text(&ctx).ends_with("\n[daemon]\naudit_log = \"~/logs/audit.log\"\n"), "{}", text(&ctx));
        assert!(report.text.contains("take effect when the daemon restarts"), "{}", report.text);
        // The same socket twice is invalid.
        args.audit_log = None;
        args.socket = Some("/run/a.sock".into());
        args.forward_socket = Some("/run/a.sock".into());
        let message = format!("{:#}", daemon_set(&ctx, &args, &mut report).unwrap_err());
        assert!(message.contains("every socket needs its own"), "{message}");
        args.socket = None;
        args.forward_socket = None;
        args.unset = vec![DaemonKeyArg::AuditLog];
        daemon_set(&ctx, &args, &mut report).unwrap();
        assert_eq!(text(&ctx), format!("{TEXT}\n[daemon]\n"));
    }

    #[test]
    fn gpg() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut report = Report::default();
        let args = GpgSetArgs {
            socket: Some("gpgconf:agent-extra-socket".into()),
            unset_socket: false,
            write: WriteArgs { dry_run: true },
        };
        gpg_set(&ctx, &args, &mut report).unwrap();
        assert!(
            report.text.contains("+[gpg]\n+socket = \"gpgconf:agent-extra-socket\"\n"),
            "{}",
            report.text
        );
        assert_eq!(text(&ctx), TEXT);
        gpg_set(&ctx, &GpgSetArgs { write: WriteArgs::default(), ..args }, &mut report).unwrap();
        super::super::profile::profile(
            &ctx,
            &crate::cli::ProfileCommand::Set(crate::cli::ProfileSetArgs {
                name: "dev".into(),
                settings: vec!["gpg=sign".into()],
                unset: Vec::new(),
                write: WriteArgs::default(),
            }),
            &mut report,
        )
        .unwrap();
        let message = format!("{:#}", gpg_remove(&ctx, &WriteArgs::default(), &mut report).unwrap_err());
        assert!(message.contains("credential-bridge-ctl profile set dev gpg=none"), "{message}");
    }

    /// `gpg set` without an option keeps the socket; each outcome is reported as what
    /// happened.
    #[test]
    fn gpg_set_keeps_changes_or_removes_the_socket() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let run = |socket: Option<&str>, unset_socket: bool| {
            let args =
                GpgSetArgs { socket: socket.map(str::to_owned), unset_socket, write: WriteArgs::default() };
            let mut report = Report::default();
            gpg_set(&ctx, &args, &mut report).unwrap();
            report.lines[0].to_string()
        };
        assert!(run(None, false).contains("[gpg] added in"));
        assert!(text(&ctx).ends_with("\n[gpg]\n"), "{}", text(&ctx));
        assert!(run(None, false).contains("unchanged"));
        assert!(run(Some("/run/gpg.sock"), false).contains("[gpg] changed: socket = /run/gpg.sock in"));
        let line = run(None, false);
        assert!(line.contains("unchanged"), "{line}");
        assert!(text(&ctx).ends_with("[gpg]\nsocket = \"/run/gpg.sock\"\n"), "{}", text(&ctx));
        assert!(run(None, true).contains("[gpg] changed: socket removed"));
        assert!(text(&ctx).ends_with("\n[gpg]\n"), "{}", text(&ctx));

        write_config(&ctx, TEXT);
        assert!(run(Some("/run/gpg.sock"), false).contains("[gpg] added with socket = /run/gpg.sock in"));
    }
}
