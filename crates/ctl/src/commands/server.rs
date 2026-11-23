//! `server add|list|show|set|remove|uninstall|ssh-config`.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use credential_bridge_config::host_keys::{HostKeyMap, HostKeyWarning};
use credential_bridge_config::known_hosts::{self, KnownHosts};
use credential_bridge_config::{
    Config, Confirm, KeySelection, Profile, Server, ServerKeys, Signing, SourceKind,
};
use credential_bridge_platform::ssh_client::{SESSION_BIND_SINCE, parse_version_output};
use credential_bridge_proto::agent::AgentClient;
use credential_bridge_proto::ipc::control::{Request, Response};

use credential_bridge_config::edit::{ConfigDocument, EditError, HostKeysEntry};

use super::change::{Change, apply, apply_doc, edit_error};
use super::probe;
use super::{CONTROL_TIMEOUT, Context, VERSION, connect, load_config, printable};
use crate::cli::{
    ServerAddArgs, ServerNameArg, ServerRemoveArgs, ServerSetArgs, ServerUninstallArgs, SshConfigArgs,
};
use crate::control::ControlError;
use crate::remote::{self, REMOTE_BINARY, RemoteShell, SshShell, SshTarget, UsedHostKey};
use crate::report::{Line, Report, Status};
use crate::ssh_config::{self, EffectiveSshConfig};

/// `server add`: registers the server by its host keys (a new server follows its
/// known_hosts entry, `known_host`; with `--pin` the keys known_hosts lists now are
/// pinned as `host_keys`, with `--follow` a pinned server follows again, without either
/// an existing server keeps its mode), installs credential-bridge-remote in
/// `~/.local/bin` on the server, runs its `setup` with the profile's git hosts and
/// signing, writes `[server.<name>]`, probes the result through the daemon, and reports
/// each step like the example in docs/architecture.md (including a hint when
/// ~/.ssh/config lacks `ForwardAgent` to the proxy). Running it again brings an
/// out-of-date server up to date; a pinned server keeps its pinned keys, and is refused
/// if ssh used a key that is not among them (`--pin` pins again).
pub fn server_add(ctx: &Context, args: &ServerAddArgs) -> anyhow::Result<()> {
    server_add_with(ctx, args, &SshShell, &mut Report::printing())
}

/// How often `server add --pin` scans a server for the key in its host certificate, and
/// the pause between scans (a scan may fail against sshd's `PerSourcePenalties`).
const KEYSCAN_ATTEMPTS: usize = 3;
const KEYSCAN_PAUSE: Duration = Duration::from_secs(2);

/// [`server_add`] with an explicit shell and report.
///
/// Order: reach the server (`uname -sm`, which also lets ssh ask about an unknown host
/// key and notes the host key ssh accepted), read its keys from known_hosts (where
/// `ssh -G` says ssh looks them up) and require the used key among them (with `--pin`
/// also a key ssh verified through a pattern line, or the key in a host certificate
/// whose CA ssh found there, checked with `ssh-keyscan`; without flags a pinned server
/// instead requires it among its pinned keys and reads nothing), validate the entry as
/// it will be written and refuse keys another server has, install the binary, write the
/// configuration, reload the daemon, set up git, check the ssh config, probe. Steps
/// before the configuration is written abort on failure; later failures are reported
/// and make the command fail at the end, keeping the entry.
pub fn server_add_with(
    ctx: &Context,
    args: &ServerAddArgs,
    shell: &dyn RemoteShell,
    report: &mut Report,
) -> anyhow::Result<()> {
    add_with(ctx, args, shell, report, KEYSCAN_PAUSE)
}

/// [`server_add_with`] with the pause between key scans.
fn add_with(
    ctx: &Context,
    args: &ServerAddArgs,
    shell: &dyn RemoteShell,
    report: &mut Report,
    keyscan_pause: Duration,
) -> anyhow::Result<()> {
    let name = args.name.as_str();
    let config = load_config(ctx).context("fix the configuration before adding a server")?;
    if args.profile == credential_bridge_config::UNREGISTERED_PROFILE {
        bail!(
            "profile.unregistered is for hosts without a [server.*] entry; \
             give {name} a profile of its own in {}",
            ctx.config_path.display()
        );
    }
    if !config.profiles.contains_key(&args.profile) {
        let known: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
        bail!(
            "profile {:?} does not exist in {} (known: {})",
            args.profile,
            ctx.config_path.display(),
            if known.is_empty() { "none".to_owned() } else { known.join(", ") }
        );
    }
    let existing = config.servers.get(name);
    // --pin pins (again) with the keys read now, --follow follows; without either an
    // existing server keeps its mode and a new one follows. A pinned server keeps its
    // very keys: they are not read again.
    let explicit_pin = args.pin;
    let kept = match existing.map(|server| &server.keys) {
        Some(ServerKeys::Pinned(old)) if !explicit_pin && !args.follow => Some(old.as_slice()),
        _ => None,
    };
    let pin = explicit_pin || kept.is_some();

    // 1. Reach the server, find its architecture and the host key ssh accepted.
    let (uname, used) = shell
        .run_noting_host_key(name, &["uname", "-sm"])
        .with_context(|| format!("cannot run ssh {name}"))?;
    if !uname.success() {
        bail!("cannot reach {name}: {}", printable(&uname.failure_reason()));
    }
    let target = server_target(&uname.stdout)?;
    let Some(used) = used else {
        bail!(
            "cannot tell which host key ssh used for {name}: its debug output (ssh -v) names none; \
             OpenSSH {SESSION_BIND_SINCE} or later is needed"
        );
    };

    // 2. Where ssh looks up the server's host keys, and the keys listed there (not read
    // for a pinned server that keeps its keys).
    let ssh_g = shell.ssh_g(name)?;
    let ssh = SshTarget::parse(&ssh_g);
    let lookup = ssh.lookup_name();
    let files = ssh.known_hosts_files(&ctx.paths.home).map_err(anyhow::Error::msg)?;
    let used_fingerprint = |key: &ssh_key::PublicKey| sha256(key) == used.fingerprint;

    // 3. The keys that identify the server: those known_hosts lists for it, which must
    // include the one ssh used, else the daemon would not recognise the server. With
    // --pin the key ssh used is enough, if ssh verified it against known_hosts. A pinned
    // server keeps its keys if the one ssh used is among them (for a host certificate:
    // the key in it).
    let (pinned, keys, origin) = if let Some(old) = kept {
        if !old.iter().any(used_fingerprint) {
            bail!(
                "the host key ssh used ({}) is not pinned for {name}; check the host key change, then run \
                 server add {name} --pin",
                used.describe()
            );
        }
        (old.to_vec(), Vec::new(), None)
    } else {
        if let Some(problem) = known_hosts::lookup_name_problem(&lookup) {
            bail!("ssh -G {name} gives the known_hosts name {lookup:?}, which {problem}");
        }
        let read = read_known_hosts(&files, report);
        let keys = known_hosts::host_keys(read.iter().map(|(_, known)| known), &lookup);
        let (pinned, origin) = if keys.iter().any(used_fingerprint) {
            (keys.clone(), None)
        } else {
            let found =
                Unlisted { name, used: &used, lookup: &lookup, files: &files, read: &read, keys: &keys };
            found.key(pin, &ssh, shell, keyscan_pause)?
        };
        (pinned, keys, origin)
    };
    report.push(Line::ok(
        "host key",
        format!(
            "{} (used by ssh{})",
            used.describe(),
            if used.certificate { ", host certificate" } else { "" }
        ),
    ));

    // 4. Follow known_hosts or pin. Kept keys are written as they were, comments
    // included.
    let key_lines: Vec<String> = match kept {
        Some(_) => pinned.iter().filter_map(|key| key.to_openssh().ok()).collect(),
        None => pinned.iter().filter_map(key_line).collect(),
    };
    let types = |keys: &[ssh_key::PublicKey]| {
        keys.iter().map(|key| key.algorithm().to_string()).collect::<Vec<_>>().join(", ")
    };
    let file_list = (files != known_hosts::default_files(&ctx.paths.home))
        .then(|| files.iter().map(|file| home_relative(file, &ctx.paths.home)).collect::<Vec<_>>());
    let entry = if pin {
        HostKeysEntry::Pinned(&key_lines)
    } else {
        HostKeysEntry::KnownHost { name: &lookup, files: file_list.as_deref() }
    };
    let (label, detail) = if kept.is_some() {
        (
            "host keys pinned",
            format!("{} (unchanged; --pin pins the keys known_hosts lists now)", types(&pinned)),
        )
    } else if pin {
        let origin = origin.map_or_else(String::new, |origin| format!(" ({origin})"));
        ("host keys pinned", format!("{}{origin}", types(&pinned)))
    } else {
        ("known_hosts", format!("{lookup}: {} (followed)", types(&keys)))
    };
    let mut status = Status::Ok;
    let mut hints = Vec::new();
    match existing.map(|server| &server.keys) {
        Some(ServerKeys::Pinned(_)) if kept.is_some() => {}
        Some(ServerKeys::Pinned(old)) if pin => {
            let old: Vec<String> = old.iter().filter_map(key_line).collect();
            if !old.iter().all(|key| key_lines.contains(key)) {
                status = Status::Warn;
                hints.push("the previously pinned keys were replaced".to_owned());
            } else if !key_lines.iter().all(|key| old.contains(key)) {
                status = Status::Warn;
                hints.push("keys were pinned in addition to the previous ones".to_owned());
            }
        }
        Some(ServerKeys::Pinned(_)) => {
            status = Status::Warn;
            hints.push("pinned before; now known_hosts is followed".to_owned());
        }
        Some(ServerKeys::KnownHost(_)) if pin => hints.push(
            "followed known_hosts before; now pinned (a rotated key needs server add --pin again)".to_owned(),
        ),
        _ => {}
    }
    if !pin && !ssh.updates_host_keys() {
        hints.push(format!(
            "ssh does not learn new host keys of {name} by itself (UpdateHostKeys is off, as OpenSSH sets it \
             when UserKnownHostsFile is set): after a host key change, ssh {name} asks, and the bridge \
             follows once you accept the new key"
        ));
    }
    let mut line = match status {
        Status::Warn => Line::warn(label, detail),
        _ => Line::ok(label, detail),
    };
    if !hints.is_empty() {
        line = line.with_hint(hints.join("\n"));
    }
    report.push(line);

    // 5. The entry as it will be written: it must validate, and its keys must be this
    // server's alone, before anything is installed.
    let git_config = !args.no_git_config && existing.is_none_or(|server| server.git_config);
    let planned = planned_config(ctx, name, &entry, &args.profile, git_config)?;
    // Files read above have had their warnings.
    let reported = if kept.is_some() { &[][..] } else { &files[..] };
    refuse_shared_keys(&planned, name, reported, report)?;
    if args.dry_run {
        apply(ctx, true, report, "", |doc| doc.set_server(name, &entry, &args.profile, git_config))?;
        report.push(Line::ok("dry run", format!("nothing installed on {name}")));
        return Ok(());
    }

    // 6. Install the remote binary.
    let local = local_remote_binary(args.remote_binary.as_deref(), target)?;
    shell
        .install_file(name, &local, REMOTE_BINARY)
        .with_context(|| format!("cannot install {REMOTE_BINARY}"))?;
    let version = shell.run(name, &[REMOTE_BINARY, "--version"])?;
    if !version.success() {
        report.push(Line::fail("remote installed", printable(&version.failure_reason())));
        bail!("the installed credential-bridge-remote does not run on {name}");
    }
    report.push(Line::ok("remote installed", printable(version.stdout.trim())));

    // 7. Write the configuration and tell the daemon. The git setup follows at once, so
    // no hint that it is out of date.
    let summary = format!("[server.{name}]");
    let doc = ConfigDocument::open(&ctx.config_path).map_err(edit_error)?;
    let change = Change { sets_up: Some(name), ..Change::default() };
    let applied = apply_doc(ctx, doc, change, report, |doc| {
        doc.set_server(name, &entry, &args.profile, git_config).map(|()| summary)
    })?;
    let config = match applied {
        Some(applied) => applied.config,
        None => load_config(ctx)?,
    };
    let server = config.servers.get(name).context("the server entry vanished after saving")?;

    // 8. git setup on the server.
    git_setup(&config, server, shell, report);

    // 9. The user's ssh config, and an ssh client too old to let servers be recognised.
    report.push(ssh_config_line(ctx, &config, name, &ssh_g));
    let client = ssh_client_line(shell);
    if client.status != Status::Ok {
        report.push(client);
    }

    // 10. One real connection through the daemon.
    report.push(probe::probe(&config, server, shell));

    if report.failed() {
        bail!(
            "{name} is configured, but not every step succeeded; [server.{name}] stays in {}: fix what failed, \
             then run credential-bridge-ctl check {name}",
            ctx.config_path.display()
        );
    }
    Ok(())
}

/// A host whose key ssh used is not among the keys known_hosts lists under its exact
/// name.
struct Unlisted<'a> {
    name: &'a str,
    used: &'a UsedHostKey,
    lookup: &'a str,
    files: &'a [PathBuf],
    /// The files that were read, with their contents.
    read: &'a [(PathBuf, KnownHosts)],
    keys: &'a [ssh_key::PublicKey],
}

impl Unlisted<'_> {
    /// How ssh verified the host key, if it found it in one of the files read here:
    /// `Some(true)` through the CA of a host certificate, `Some(false)` as a plain key.
    fn verified(&self) -> Option<bool> {
        let found = self.used.verified.as_ref()?;
        self.read.iter().any(|(path, _)| *path == found.file).then_some(found.authority)
    }

    /// The error when ssh connected without known_hosts vouching for the key.
    fn unverified(&self) -> anyhow::Error {
        anyhow::anyhow!(
            "ssh did not verify the host key of {name} ({}) against known_hosts (StrictHostKeyChecking=no?), \
             so nothing was pinned; connect once with host key checking on, then run server add again",
            self.used.describe(),
            name = self.name
        )
    }

    /// The key to pin and where it came from, or why the host cannot be registered.
    /// Following known_hosts needs an exact entry. With `pin`, ssh must have verified
    /// the key against a file read here (its debug log says where it found the key or
    /// the CA): then a plain key may come from any host line (the line's pattern does not
    /// matter), the key in a host certificate from `ssh-keyscan`.
    fn key(
        &self,
        pin: bool,
        ssh: &SshTarget,
        shell: &dyn RemoteShell,
        pause: Duration,
    ) -> anyhow::Result<(Vec<ssh_key::PublicKey>, Option<String>)> {
        let (name, used, lookup) = (self.name, self.used, self.lookup);
        let verified = self.verified();
        // A certificate whose CA ssh did not know may still have been verified as a
        // plain key: then the plain key counts.
        if used.certificate && verified != Some(false) {
            if !pin {
                bail!(
                    "ssh {name} trusts the host certificate of {} through @cert-authority, and known_hosts does \
                     not list the key in it under {lookup}: following known_hosts does not follow certificate authorities, \
                     so the daemon would not recognise {name}. Run this again with --pin to pin the key in the \
                     certificate",
                    used.describe()
                );
            }
            if verified != Some(true) {
                return Err(self.unverified());
            }
            let key = certified_key(shell, ssh, name, used, pause)?;
            return Ok((
                vec![key],
                Some("the key in the host certificate, checked with ssh-keyscan".to_owned()),
            ));
        }
        match (
            known_hosts::key_with_fingerprint(self.read.iter().map(|(_, known)| known), &used.fingerprint),
            pin,
        ) {
            (Some(_), true) if verified != Some(false) => Err(self.unverified()),
            (Some(key), true) => Ok((
                vec![key],
                Some(format!("the key ssh used; known_hosts lists it, but not under {lookup}")),
            )),
            (Some(_), false) => bail!(
                "known_hosts lists the host key ssh used for {name} ({}) only under a pattern or another name, \
                 not under {lookup}: the daemon follows exact names only. Run this again with --pin to pin \
                 the key, or add an exact entry for {lookup}",
                used.describe()
            ),
            (None, _) if self.keys.is_empty() => bail!(
                "known_hosts has no host key for {lookup} (looked in {}): connect once with `ssh {name}` and \
                 confirm the host key, then run this again",
                self.files.iter().map(|file| file.display().to_string()).collect::<Vec<_>>().join(", ")
            ),
            (None, _) => bail!(
                "ssh {name} used the host key {}, but known_hosts lists other keys for {lookup} ({}); the daemon \
                 would not recognise {name}. Check HostKeyAlias and known_hosts for {name}, then run this again",
                used.describe(),
                self.keys.iter().map(fingerprint).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

/// The plain key of a server that showed ssh a host certificate: `ssh-keyscan` for the
/// certificate's key type, accepted only if it is the key in the certificate (its
/// fingerprint as ssh reported it). Up to [`KEYSCAN_ATTEMPTS`] scans, `pause` apart.
fn certified_key(
    shell: &dyn RemoteShell,
    ssh: &SshTarget,
    name: &str,
    used: &UsedHostKey,
    pause: Duration,
) -> anyhow::Result<ssh_key::PublicKey> {
    let key_type = keyscan_type(&used.algorithm)
        .with_context(|| format!("ssh-keyscan cannot ask for {} keys; nothing was pinned", used.algorithm))?;
    let (hostname, port) = (ssh.hostname(), ssh.port());
    let mut offered: Vec<String> = Vec::new();
    for attempt in 0..KEYSCAN_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(pause);
        }
        let text = shell.keyscan(hostname, port, key_type).context("cannot run ssh-keyscan")?;
        for key in scanned_keys(&text) {
            if sha256(&key) == used.fingerprint {
                return Ok(key);
            }
            if !offered.contains(&fingerprint(&key)) {
                offered.push(fingerprint(&key));
            }
        }
    }
    let scan = format!("ssh-keyscan -t {key_type} -p {port} {hostname}");
    if offered.is_empty() {
        bail!(
            "{scan} returned no key in {KEYSCAN_ATTEMPTS} attempts, so the key in the host certificate of {name} \
             cannot be pinned (ssh-keyscan connects directly, without ProxyJump); nothing was pinned"
        );
    }
    bail!(
        "{scan} returned {}, not the key in the host certificate ssh {name} used ({}); nothing was pinned",
        offered.join(", "),
        used.describe()
    )
}

/// The `ssh-keyscan -t` name for a key type as ssh's debug log names it.
fn keyscan_type(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "ssh-ed25519" => Some("ed25519"),
        "ssh-rsa" => Some("rsa"),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => Some("ecdsa"),
        "sk-ssh-ed25519@openssh.com" => Some("ed25519-sk"),
        "sk-ecdsa-sha2-nistp256@openssh.com" => Some("ecdsa-sk"),
        _ => None,
    }
}

/// The keys in `ssh-keyscan` output (`host type base64` lines; comments skipped).
fn scanned_keys(text: &str) -> Vec<ssh_key::PublicKey> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace().skip(1);
            let (kind, data) = (fields.next()?, fields.next()?);
            ssh_key::PublicKey::from_openssh(&format!("{kind} {data}")).ok()
        })
        .collect()
}

/// The configuration with `[server.<name>]` as `server add` would write it, validated
/// like the daemon loads it; nothing is written.
fn planned_config(
    ctx: &Context,
    name: &str,
    entry: &HostKeysEntry<'_>,
    profile: &str,
    git_config: bool,
) -> anyhow::Result<Config> {
    let mut doc = ConfigDocument::open(&ctx.config_path).map_err(edit_error)?;
    doc.set_server(name, entry, profile, git_config).map_err(edit_error)?;
    doc.check(&ctx.paths)
        .map_err(edit_error)
        .with_context(|| format!("[server.{name}] would not be accepted; nothing was installed or written"))
}

/// Fails if a host key of `name` in `config` also belongs to another server: a key of
/// two servers selects neither, so a working server would stop being recognised. A
/// known_hosts file of another server that cannot be read is a warning: a key in it is
/// not compared (`reported`: files already warned about).
fn refuse_shared_keys(
    config: &Config,
    name: &str,
    reported: &[PathBuf],
    report: &mut Report,
) -> anyhow::Result<()> {
    let read = probe::HostKeys::read(config);
    let mut shared: Vec<String> = Vec::new();
    for warning in &read.warnings {
        match warning {
            HostKeyWarning::Unreadable { path, error } if !reported.contains(path) => report.push(
                Line::warn("known_hosts file", probe::unreadable_text(path, error))
                    .with_hint("keys in it are not compared with the new server's"),
            ),
            HostKeyWarning::Ambiguous { key, servers } if servers.iter().any(|server| server == name) => {
                let others: Vec<&str> =
                    servers.iter().map(String::as_str).filter(|other| *other != name).collect();
                shared.push(format!("{} also belongs to server {}", fingerprint(key), others.join(", ")));
            }
            _ => {}
        }
    }
    if shared.is_empty() {
        return Ok(());
    }
    bail!(
        "the host keys of {name} must be its own: {}. A key of two servers selects neither, so both would be \
         treated as unregistered; remove the other entry or fix its known_hosts entry, then run this again \
         (nothing was installed or written)",
        shared.join("; ")
    )
}

/// The known_hosts `files` that exist and can be read, with their contents. One that
/// cannot be read (no permission, not a regular file, too large) is skipped with a
/// warning, as ssh skips it and the daemon does.
fn read_known_hosts(files: &[PathBuf], report: &mut Report) -> Vec<(PathBuf, KnownHosts)> {
    let mut read = Vec::new();
    for file in files {
        match KnownHosts::read(file) {
            Ok(Some(known)) => read.push((file.clone(), known)),
            Ok(None) => {}
            Err(error) => {
                report.push(Line::warn("known_hosts file", probe::unreadable_text(file, &error.to_string())));
            }
        }
    }
    read
}

/// `SHA256:…` of a key.
fn sha256(key: &ssh_key::PublicKey) -> String {
    key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
}

/// `path` with the home directory written as `~/`.
fn home_relative(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// The architecture of a server from `uname -sm`; only Linux is supported.
fn server_target(uname: &str) -> anyhow::Result<&'static str> {
    let mut fields = uname.split_whitespace();
    let (os, arch) = (fields.next().unwrap_or_default(), fields.next().unwrap_or_default());
    if os != "Linux" {
        bail!("only Linux servers are supported; this one runs {:?}", printable(os));
    }
    remote::remote_target(arch)
        .with_context(|| format!("no credential-bridge-remote for {:?}", printable(arch)))
}

/// The binary to upload: `--remote-binary` or the bundled one for `target`.
fn local_remote_binary(explicit: Option<&Path>, target: &str) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_file() {
            bail!("{} does not exist", path.display());
        }
        return Ok(path.to_owned());
    }
    let env_dir = std::env::var_os(remote::HELPER_DIR_ENV).map(PathBuf::from);
    let exe = std::env::current_exe().ok();
    let dirs = remote::helper_dirs(env_dir.as_deref(), exe.as_deref());
    remote::find_bundled_binary(&dirs, target).with_context(|| {
        format!(
            "no bundled {} found (looked in {}); pass --remote-binary PATH",
            remote::bundled_binary_name(target),
            dirs.iter().map(|dir| dir.display().to_string()).collect::<Vec<_>>().join(", ")
        )
    })
}

/// `ssh-ed25519 SHA256:…`.
pub(crate) fn fingerprint(key: &ssh_key::PublicKey) -> String {
    format!("{} {}", key.algorithm(), key.fingerprint(ssh_key::HashAlg::Sha256))
}

/// A key as `type base64`, without comment.
fn key_line(key: &ssh_key::PublicKey) -> Option<String> {
    ssh_key::PublicKey::new(key.key_data().clone(), "").to_openssh().ok()
}

/// The `credential-bridge-remote setup` arguments for a server: `--host` for every git
/// host, `--http-path` where needed, `--signing-key`, `--print` with
/// `git_config = false`.
pub(crate) fn setup_argv(hosts: &[(String, bool)], signing_key: Option<&str>, print: bool) -> Vec<String> {
    let mut argv = vec![REMOTE_BINARY.to_owned(), "setup".to_owned()];
    for (host, _) in hosts {
        argv.extend(["--host".to_owned(), host.clone()]);
    }
    for (host, _) in hosts.iter().filter(|(_, http_path)| *http_path) {
        argv.extend(["--http-path".to_owned(), host.clone()]);
    }
    if let Some(key) = signing_key {
        argv.extend(["--signing-key".to_owned(), key.to_owned()]);
    }
    if print {
        argv.push("--print".to_owned());
    }
    argv
}

/// Runs `setup` on the server and reports it.
fn git_setup(config: &Config, server: &Server, shell: &dyn RemoteShell, report: &mut Report) {
    let hosts = config.git_hosts_for(server);
    let signing = config.profile_for(Some(server)).and_then(|profile| profile.signing);
    let signing_key = match signing {
        Some(Signing::Ssh) => match signing_key(config, &server.name) {
            Ok(key) => Some(key),
            Err(reason) => {
                report.push(Line::warn("ssh signing", format!("not set up: {reason}")).with_hint(format!(
                    "start the daemon, then run: credential-bridge-ctl server add {} --profile {}",
                    server.name, server.profile
                )));
                None
            }
        },
        None => None,
    };
    if hosts.is_empty() && signing_key.is_none() {
        report.push(Line::ok("git config", "nothing to set up"));
        return;
    }
    let argv = setup_argv(&hosts, signing_key.as_deref(), !server.git_config);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = match shell.run(&server.name, &argv) {
        Ok(output) => output,
        Err(error) => {
            report.push(Line::fail("git config", error.to_string()));
            return;
        }
    };
    if !output.success() {
        report.push(Line::fail("git config", printable(&output.failure_reason())));
        return;
    }
    let mut what: Vec<&str> = hosts.iter().map(|(host, _)| host.as_str()).collect();
    if signing_key.is_some() {
        what.push("ssh signing");
    }
    if server.git_config {
        report.push(Line::ok("git config", format!("{} set up", what.join(", "))));
    } else if output.stdout.trim().is_empty() {
        report.push(Line::ok("git config", "not changed (git_config = false); nothing is missing"));
    } else {
        report.push(
            Line::warn("git config", "not changed (git_config = false); run these on the server:")
                .with_hint(printable_lines(&output.stdout)),
        );
    }
}

/// Lines of server output with control characters removed.
fn printable_lines(text: &str) -> String {
    text.lines().map(printable).collect::<Vec<_>>().join("\n")
}

/// The public key for `user.signingkey`: the first key the daemon shows `server`, taken
/// in full from `agent.sock`.
pub(crate) fn signing_key(config: &Config, server: &str) -> Result<String, String> {
    let mut client = connect(&config.daemon, CONTROL_TIMEOUT).map_err(|error| match error {
        ControlError::NotRunning(_) => "the daemon is not running".to_owned(),
        other => other.to_string(),
    })?;
    let keys = match client.request(&Request::Keys { server: Some(server.to_owned()) }) {
        Ok(Response::Keys(keys)) => keys,
        Ok(_) => return Err("unexpected answer from the daemon".to_owned()),
        Err(error) => return Err(error.to_string()),
    };
    let first = keys.first().ok_or("the profile shows no ssh keys")?;
    let wanted = first.fingerprint.rsplit(' ').next().unwrap_or_default().to_owned();
    let stream =
        UnixStream::connect(&config.daemon.socket).map_err(|error| format!("agent.sock: {error}"))?;
    let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
    let identities = AgentClient::new(stream).identities().map_err(|error| format!("agent.sock: {error}"))?;
    identities
        .iter()
        .filter_map(|identity| ssh_key::PublicKey::from_bytes(&identity.key_blob).ok())
        .find(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string() == wanted)
        .and_then(|key| key_line(&key))
        .ok_or_else(|| format!("key {wanted} is not listed on agent.sock"))
}

/// Whether the user's ssh config forwards the proxy to `name`, from its `ssh -G` output.
fn ssh_config_line(ctx: &Context, config: &Config, name: &str, ssh_g: &str) -> Line {
    if EffectiveSshConfig::parse(ssh_g).forwards_to(&config.daemon.forward_socket, &ctx.paths.home) {
        Line::ok("ssh config", format!("ForwardAgent to the proxy for {name}"))
    } else {
        Line::warn("ssh config", format!("no ForwardAgent to the proxy for {name}"))
            .with_hint(format!("credential-bridge-ctl server ssh-config {name}"))
    }
}

/// Whether the local `ssh` is OpenSSH 8.9 or later: older clients send no
/// `session-bind`, so the daemon recognises no server behind them (they get no keys, no
/// tokens, no gpg). A warning, never a failure.
pub(crate) fn ssh_client_line(shell: &dyn RemoteShell) -> Line {
    const EFFECT: &str = "servers are not recognised: no keys, no tokens, no gpg";
    let hint = format!("OpenSSH {SESSION_BIND_SINCE} or later is needed to recognise servers");
    match shell.ssh_version() {
        Ok(output) => match parse_version_output(&output) {
            Some(version) if version.sends_session_bind() => {
                Line::ok("ssh client", format!("OpenSSH {version}"))
            }
            Some(version) => {
                Line::warn("ssh client", format!("OpenSSH {version} sends no session-bind: {EFFECT}"))
                    .with_hint(hint)
            }
            None => Line::warn(
                "ssh client",
                format!("not OpenSSH ({}): {EFFECT}", printable(output.lines().next().unwrap_or("").trim())),
            )
            .with_hint(hint),
        },
        Err(error) => {
            Line::warn("ssh client", format!("cannot run ssh -V: {error}: {EFFECT}")).with_hint(hint)
        }
    }
}

/// `server list`.
pub fn server_list(ctx: &Context) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    print!("{}", list_text(&config));
    Ok(())
}

/// The table `server list` prints.
fn list_text(config: &Config) -> String {
    if config.servers.is_empty() {
        return "no servers; add one with: credential-bridge-ctl server add NAME --profile PROFILE\n"
            .to_owned();
    }
    let read = probe::HostKeys::read(config);
    let width = config.servers.keys().map(String::len).max().unwrap_or(0).max(6);
    let profile_width = config.servers.values().map(|s| s.profile.len()).max().unwrap_or(0).max(7);
    let mut out = format!("{:<width$}  {:<profile_width$}  HOST KEYS\n", "SERVER", "PROFILE");
    for server in config.servers.values() {
        let mut keys = host_keys_summary(&read.map, server);
        let unreadable: Vec<String> = read
            .unreadable(config, &server.name)
            .iter()
            .map(|(path, _)| path.display().to_string())
            .collect();
        if !unreadable.is_empty() {
            keys.push_str(&format!("  [cannot read {}]", unreadable.join(", ")));
        }
        if !server.git_config {
            keys.push_str("  [git_config = false]");
        }
        out.push_str(&format!("{:<width$}  {:<profile_width$}  {keys}\n", server.name, server.profile));
    }
    out
}

/// `known_hosts box: ssh-ed25519, ssh-rsa` or `pinned: ssh-ed25519`.
fn host_keys_summary(map: &HostKeyMap, server: &Server) -> String {
    let types = |keys: &[ssh_key::PublicKey]| {
        if keys.is_empty() {
            "none".to_owned()
        } else {
            keys.iter().map(|key| key.algorithm().to_string()).collect::<Vec<_>>().join(", ")
        }
    };
    match &server.keys {
        ServerKeys::KnownHost(known) => {
            format!("known_hosts {}: {}", known.name, types(map.followed(&server.name)))
        }
        ServerKeys::Pinned(keys) => format!("pinned: {}", types(keys)),
    }
}

/// `server show`.
pub fn server_show(ctx: &Context, args: &ServerNameArg) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    let server = config.servers.get(&args.name).with_context(|| format!("no [server.{}]", args.name))?;
    print!("{}", show_text(ctx, &config, server));
    Ok(())
}

/// What `server show` prints.
fn show_text(ctx: &Context, config: &Config, server: &Server) -> String {
    let mut out = format!("server      {}\nprofile     {}\n", server.name, server.profile);
    let read = probe::HostKeys::read(config);
    let map = &read.map;
    out.push_str(&format!("host keys   {}\n", host_keys_summary(map, server)));
    let keys = match &server.keys {
        ServerKeys::KnownHost(known) => {
            if known.files != known_hosts::default_files(&ctx.paths.home) {
                let files: Vec<String> =
                    known.files.iter().map(|file| home_relative(file, &ctx.paths.home)).collect();
                out.push_str(&format!("            from {}\n", files.join(", ")));
            }
            for (path, error) in read.unreadable(config, &server.name) {
                out.push_str(&format!("            {}\n", probe::unreadable_text(path, error)));
            }
            if map.followed(&server.name).is_empty() {
                out.push_str(&format!(
                    "            known_hosts lists no key for {}: the server is treated as unregistered\n",
                    known.name
                ));
            }
            map.followed(&server.name)
        }
        ServerKeys::Pinned(keys) => keys.as_slice(),
    };
    for key in keys {
        out.push_str(&format!("            {}\n", fingerprint(key)));
    }
    for (key, servers) in map.ambiguous() {
        if servers.contains(&server.name.as_str()) {
            out.push_str(&format!(
                "            {} also belongs to {}: treated as unregistered\n",
                fingerprint(key),
                servers.iter().filter(|other| **other != server.name).copied().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    out.push_str(&format!(
        "git config  {}\n",
        if server.git_config { "managed by ctl" } else { "not touched (git_config = false)" }
    ));
    match config.profile_for(Some(server)) {
        Some(profile) => out.push_str(&profile_text(config, profile)),
        None => out.push_str("the profile does not exist: the server gets nothing\n"),
    }
    out
}

/// What a profile allows, for `server show`.
pub(crate) fn profile_text(config: &Config, profile: &Profile) -> String {
    let mut out = String::new();
    let ssh = match &profile.ssh {
        None => "no keys".to_owned(),
        Some(policy) => {
            let keys = match &policy.keys {
                KeySelection::All if config.agent.is_none() => "all keys (no [agent]: none)".to_owned(),
                KeySelection::All => "all keys".to_owned(),
                KeySelection::Upstreams(names) => format!("keys of {}", names.join(", ")),
            };
            match policy.confirm {
                Confirm::Remember(duration) => format!(
                    "{keys}, confirm each use (remembered {})",
                    credential_bridge_config::duration::format_duration(duration)
                ),
                Confirm::Always => format!("{keys}, confirm every signature"),
                Confirm::Never => keys,
            }
        }
    };
    out.push_str(&format!("ssh         {ssh}\n"));
    let gpg = match (profile.gpg.sign, profile.gpg.decrypt) {
        (false, false) => "no",
        (true, false) => "sign",
        (false, true) => "decrypt",
        (true, true) => "sign, decrypt",
    };
    out.push_str(&format!("gpg         {gpg}\n"));
    let hops: Vec<&str> = [("ssh", profile.hops.ssh), ("git", profile.hops.git), ("gpg", profile.hops.gpg)]
        .into_iter()
        .filter_map(|(name, on)| on.then_some(name))
        .collect();
    out.push_str(&format!(
        "hops        {}\n",
        if hops.is_empty() { "nothing".to_owned() } else { hops.join(", ") }
    ));
    if profile.signing == Some(Signing::Ssh) {
        out.push_str("signing     ssh (git commits signed through the agent)\n");
    }
    if profile.git.is_empty() {
        out.push_str("git         no rules: no tokens\n");
    }
    for (index, rule) in profile.git.iter().enumerate() {
        let source = config.sources.get(&rule.source);
        let mut line = format!(
            "{:<12}{} -> {} ({})",
            if index == 0 { "git" } else { "" },
            rule.url,
            rule.source,
            source.map_or("?", |source| source.kind.describe())
        );
        if !rule.permissions.is_empty() {
            let permissions: Vec<String> =
                rule.permissions.iter().map(|(name, access)| format!("{name}={}", access.as_str())).collect();
            line.push_str(&format!(" {}", permissions.join(",")));
        }
        if source.is_some_and(|source| matches!(source.kind, SourceKind::GithubApp { .. })) {
            line.push_str(&format!(" per {}", rule.per));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `server remove`.
pub fn server_remove(ctx: &Context, args: &ServerRemoveArgs) -> anyhow::Result<()> {
    server_remove_with(ctx, args, &SshShell, &mut Report::printing())
}

/// [`server_remove`] with an explicit shell and report.
///
/// `[server.<name>]` must exist in the file; that is checked before anything runs on
/// the server. With `--remote`, the server is cleaned up first (it is still registered,
/// so the bridge still gives it keys); if that fails, the entry stays so the command can
/// be repeated.
pub fn server_remove_with(
    ctx: &Context,
    args: &ServerRemoveArgs,
    shell: &dyn RemoteShell,
    report: &mut Report,
) -> anyhow::Result<()> {
    let name = args.name.as_str();
    let uninstall = format!("credential-bridge-ctl server uninstall {name}");
    let doc = ConfigDocument::open(&ctx.config_path).map_err(edit_error).with_context(|| {
        format!(
            "cannot tell whether [server.{name}] exists; nothing was changed (to clean up a server \
             without an entry, run: {uninstall})"
        )
    })?;
    if !doc.contains(&["server", name]) {
        bail!(
            "no [server.{name}] in {}; nothing was changed (to clean up a server without an entry, run: \
             {uninstall})",
            ctx.config_path.display()
        );
    }
    if args.dry_run {
        apply_doc(ctx, doc, Change::new(true), report, |doc| {
            remove_server(doc, name).map(|()| String::new())
        })?;
        if args.remote {
            report.push(Line::ok("dry run", format!("nothing uninstalled on {name}")));
        }
        return Ok(());
    }
    if args.remote {
        let output = shell.run(name, REMOTE_UNINSTALL)?;
        if !output.success() {
            report.push(Line::fail("remote removed", printable(&output.failure_reason())));
            bail!(
                "{name} was not cleaned up; the entry stays (run again without --remote to drop it anyway)"
            );
        }
        report.push(Line::ok("remote removed", "git config entries and credential-bridge-remote"));
    }
    // The server may have changed while it was cleaned up: open the file again.
    apply(ctx, false, report, &format!("[server.{name}] removed"), |doc| remove_server(doc, name))?;
    if !args.remote {
        report.push(
            Line::ok(
                "remote",
                format!("{name} keeps credential-bridge-remote and its git config, if installed"),
            )
            .with_hint(format!("to remove them: {uninstall}")),
        );
    }
    Ok(())
}

/// What runs on a server to clean it up.
const REMOTE_UNINSTALL: &[&str] = &[REMOTE_BINARY, "uninstall", "--remove-binary"];

/// `server uninstall DEST`.
pub fn server_uninstall(ctx: &Context, args: &ServerUninstallArgs) -> anyhow::Result<()> {
    server_uninstall_with(ctx, args, &SshShell, &mut Report::printing())
}

/// [`server_uninstall`] with an explicit shell and report: runs
/// `credential-bridge-remote uninstall --remove-binary` on any ssh destination through
/// the user's own ssh (and so through the proxy and its policy), and never reads or
/// changes the configuration file, except to explain a failure.
pub fn server_uninstall_with(
    ctx: &Context,
    args: &ServerUninstallArgs,
    shell: &dyn RemoteShell,
    report: &mut Report,
) -> anyhow::Result<()> {
    let dest = args.dest.as_str();
    let command = REMOTE_UNINSTALL.join(" ");
    if args.dry_run {
        report.push(Line::ok("dry run", format!("would run `{command}` on {dest}; nothing was run")));
        return Ok(());
    }
    let reason = match shell.run(dest, REMOTE_UNINSTALL) {
        Ok(output) if output.success() => {
            report.push(Line::ok("remote removed", "git config entries and credential-bridge-remote"));
            return Ok(());
        }
        Ok(output) => printable(&output.failure_reason()),
        Err(error) => error.to_string(),
    };
    report.push(Line::fail("remote removed", reason));
    let registered = load_config(ctx).ok().map(|config| config.servers.contains_key(dest));
    let login = format!(
        "the bridge gives it no keys (built-in profile.unregistered): log in another way (your own \
         key file, a password), or register it for a moment with credential-bridge-ctl server add \
         {dest} --profile PROFILE and run credential-bridge-ctl server remove {dest} --remote"
    );
    match registered {
        Some(true) => bail!("{dest} was not cleaned up"),
        Some(false) => bail!("{dest} was not cleaned up. It is not a registered server, so {login}"),
        None => bail!("{dest} was not cleaned up. If it is not a registered server, {login}"),
    }
}

/// [`ConfigDocument::remove_server`] as an edit that fails for an unknown server.
fn remove_server(doc: &mut ConfigDocument, name: &str) -> Result<(), EditError> {
    if doc.remove_server(name) {
        Ok(())
    } else {
        Err(EditError::NotFound { table: format!("server.{name}") })
    }
}

/// `server set NAME --profile P`: changes the profile. If the server's git setup (hosts,
/// signing) differs under the new profile, [`apply`] says how to bring it up to date.
pub fn server_set(ctx: &Context, args: &ServerSetArgs, report: &mut Report) -> anyhow::Result<()> {
    let name = args.name.as_str();
    let summary = format!("[server.{name}] profile = {}", args.profile);
    apply(ctx, args.write.dry_run, report, &summary, |doc| doc.set_server_profile(name, &args.profile))?;
    Ok(())
}

/// `server ssh-config`: prints [`crate::ssh_config::suggestion`]. Without `--fallback` both
/// variants are printed: the simple one and the one with a fallback agent.
pub fn ssh_config(ctx: &Context, args: &SshConfigArgs) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    print!("{}", ssh_config_text(ctx, &config, args)?);
    Ok(())
}

/// What `server ssh-config` prints.
fn ssh_config_text(ctx: &Context, config: &Config, args: &SshConfigArgs) -> anyhow::Result<String> {
    for server in &args.servers {
        if !config.servers.contains_key(server) {
            bail!(
                "no [server.{server}]; add it first with: credential-bridge-ctl server add {server} --profile PROFILE"
            );
        }
    }
    let servers: Vec<&str> = if args.servers.is_empty() {
        config.servers.keys().map(String::as_str).collect()
    } else {
        args.servers.iter().map(String::as_str).collect()
    };
    let (agent, forward, home) = (&config.daemon.socket, &config.daemon.forward_socket, &ctx.paths.home);
    let mut out = String::from("# Add to ~/.ssh/config (credential-bridge-ctl never edits it).\n");
    if let Some(fallback) = &args.fallback {
        let fallback = ctx.paths.expand_home(fallback);
        out.push_str("# Falls back to another agent when the daemon is not running.\n");
        out.push_str(&ssh_config::suggestion(&servers, agent, forward, home, Some(&fallback)));
        return Ok(out);
    }
    out.push_str("\n# Variant 1: always use the proxy.\n");
    out.push_str(&ssh_config::suggestion(&servers, agent, forward, home, None));
    out.push_str(
        "\n# Variant 2: fall back to another agent when the daemon is not running.\n\
         # Replace FALLBACK_AGENT_SOCKET, or run: credential-bridge-ctl server ssh-config --fallback SOCKET\n",
    );
    out.push_str(&ssh_config::suggestion(
        &servers,
        agent,
        forward,
        home,
        Some(Path::new("FALLBACK_AGENT_SOCKET")),
    ));
    if servers.is_empty() {
        out.push_str(
            "\n# No servers yet: add them with credential-bridge-ctl server add NAME --profile PROFILE\n",
        );
    }
    Ok(out)
}

/// The remote binary's version line as `--version` prints it for this release.
pub(crate) fn expected_remote_version() -> String {
    format!("credential-bridge-remote {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{FakeShell, context, test_key, write_config};
    use crate::remote::KnownHostsMatch;

    const CONFIG: &str = r#"# my configuration
version = 2

[source.github]
type = "github"
auth = "gh"

[source.gitlab]
type  = "gitlab"
host  = "gitlab.example.com"
auth  = "token"
token = "bw://gitlab-team/token"

# the build profile
[profile.build]
ssh = { keys = "all" }

[[profile.build.git]]
url    = "https://github.com/my-org/*"
source = "github"

[[profile.build.git]]
url    = "https://gitlab.example.com/team/*"
source = "gitlab"

[profile.dev]
ssh = { keys = "all", confirm = "8h" }
"#;

    fn add_args(name: &str, profile: &str, binary: &Path) -> ServerAddArgs {
        ServerAddArgs {
            name: name.into(),
            profile: profile.into(),
            no_git_config: false,
            pin: false,
            follow: false,
            remote_binary: Some(binary.to_owned()),
            dry_run: false,
        }
    }

    /// Lets `~/.ssh/known_hosts` of the test home list `key` for `host` (replacing what
    /// it listed for `host`), as ssh stores an accepted host key.
    fn known_host(ctx: &Context, host: &str, key: &str) {
        let path = ctx.paths.home.join(".ssh/known_hosts");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        let mut text: String = old
            .lines()
            .filter(|line| !line.starts_with(&format!("{host} ")))
            .map(|line| format!("{line}\n"))
            .collect();
        text.push_str(&format!("{host} {key}\n"));
        std::fs::write(&path, text).unwrap();
    }

    /// `ssh -G` output for `host`: OpenSSH's default known_hosts files (in the test home)
    /// and `ForwardAgent` to the proxy.
    fn ssh_g(ctx: &Context, host: &str) -> String {
        let (home, forward) = (ctx.paths.home.display(), ctx.paths.forward_socket.display());
        format!(
            "hostname {host}\nport 22\nuserknownhostsfile {home}/.ssh/known_hosts {home}/.ssh/known_hosts2\n\
             globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2\nforwardagent {forward}\n"
        )
    }

    /// A server `buildserver` whose host key (seed 7) is in known_hosts and used by ssh.
    fn shell(ctx: &Context) -> FakeShell {
        shell_for(ctx, "buildserver", 7)
    }

    /// A server `host` whose host key (`seed`) is in known_hosts and used by ssh.
    fn shell_for(ctx: &Context, host: &str, seed: u8) -> FakeShell {
        known_host(ctx, host, &test_key(seed));
        FakeShell { host_key: Some(test_key(seed)), ssh_g: ssh_g(ctx, host), ..FakeShell::default() }
            .answer("uname", 0, "Linux x86_64\n")
            .answer(&format!("{REMOTE_BINARY} --version"), 0, &format!("{}\n", expected_remote_version()))
            .answer(&format!("{REMOTE_BINARY} setup"), 0, "")
            .answer(&format!("{REMOTE_BINARY} uninstall"), 0, "")
    }

    fn binary(dir: &Path) -> PathBuf {
        let path = dir.join("credential-bridge-remote");
        std::fs::write(&path, b"#!/bin/true\n").unwrap();
        path
    }

    #[test]
    fn add_follows_known_hosts_installs_sets_up_and_keeps_comments() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let shell = shell(&ctx);
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("buildserver", "build", &binary(dir.path())), &shell, &mut report)
            .unwrap();

        // ssh -G once; no ssh-keyscan, nothing but the steps.
        assert_eq!(shell.ssh_g_runs.get(), 1);
        assert_eq!(
            shell.commands(),
            vec![
                "uname -sm".to_owned(),
                format!("install {REMOTE_BINARY}"),
                format!("{REMOTE_BINARY} --version"),
                format!(
                    "{REMOTE_BINARY} setup --host github.com --host gitlab.example.com --http-path github.com --http-path gitlab.example.com"
                ),
            ]
        );
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.starts_with("# my configuration\n"), "{text}");
        assert!(text.contains("# the build profile"));
        assert!(
            text.contains("[server.buildserver]\nknown_host = \"buildserver\"\nprofile = \"build\"\n"),
            "{text}"
        );
        assert!(!text.contains("host_keys") && !text.contains("known_hosts_files"), "{text}");
        assert!(!text.contains("git_config"));

        let labels: Vec<(&str, crate::report::Status)> =
            report.lines.iter().map(|line| (line.label.as_str(), line.status)).collect();
        use crate::report::Status::{Ok, Warn};
        assert_eq!(
            labels,
            vec![
                ("host key", Ok),
                ("known_hosts", Ok),
                ("remote installed", Ok),
                ("config", Ok),
                ("daemon", Warn),
                ("git config", Ok),
                ("ssh config", Ok),
                ("probe", Warn),
            ]
        );
        assert!(report.lines[0].detail.starts_with("ssh-ed25519 SHA256:"), "{}", report.lines[0].detail);
        assert!(report.lines[0].detail.ends_with(" (used by ssh)"), "{}", report.lines[0].detail);
        assert_eq!(report.lines[1].detail, "buildserver: ssh-ed25519 (followed)");
        assert_eq!(report.lines[5].detail, "github.com, gitlab.example.com set up");
        assert_eq!(report.lines[7].detail, "skipped: the daemon is not running");
    }

    /// `--pin` writes the keys known_hosts lists as `host_keys`; running server add
    /// again switches between the modes and keeps `git_config = false`.
    #[test]
    fn add_again_switches_modes_and_keeps_git_config_false() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let bin = binary(dir.path());
        let mut args = add_args("devbox", "dev", &bin);
        args.no_git_config = true;
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 7), &mut Report::default()).unwrap();
        let first = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(first.contains("known_host = \"devbox\"") && first.contains("git_config = false"), "{first}");

        // Pinned, with a new host key and another profile, without the flag.
        args.no_git_config = false;
        args.pin = true;
        args.profile = "build".into();
        let shell = shell_for(&ctx, "devbox", 8);
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        let second = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert_eq!(second.matches("[server.devbox]").count(), 1);
        assert!(
            second.contains(&format!(
                "[server.devbox]\nhost_keys = [\"{}\"]\nprofile = \"build\"\ngit_config = false\n",
                test_key(8)
            )),
            "{second}"
        );
        assert!(!second.contains("known_host"), "{second}");
        let pinned = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!((pinned.status, pinned.detail.as_str()), (Status::Ok, "ssh-ed25519"));
        assert!(pinned.hint.as_deref().unwrap().starts_with("followed known_hosts before"), "{pinned:?}");
        // git_config = false: setup only prints.
        assert!(shell.commands().last().unwrap().ends_with("--print"));

        // Pinned again after the server's key changed: a warning.
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 9), &mut report).unwrap();
        let pinned = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(pinned.status, Status::Warn);
        assert!(std::fs::read_to_string(&ctx.config_path).unwrap().contains(&test_key(9)));

        // Without a flag a pinned server stays pinned with its keys; a key ssh used that
        // is not among them is refused (pinned_servers_keep_their_keys).
        args.pin = false;
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 9), &mut Report::default()).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("host_keys = [\"{}\"]", test_key(9))), "{text}");
        assert!(!text.contains("known_host ="), "{text}");

        // Back to following known_hosts with --follow: a warning.
        args.follow = true;
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 10), &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(
            text.contains(
                "[server.devbox]\nknown_host = \"devbox\"\nprofile = \"build\"\ngit_config = false\n"
            ),
            "{text}"
        );
        let line = report.lines.iter().find(|line| line.label == "known_hosts").unwrap();
        assert_eq!(line.status, Status::Warn);
        assert_eq!(line.hint.as_deref(), Some("pinned before; now known_hosts is followed"));

        // Without a flag a followed server keeps following, also after a key change.
        args.follow = false;
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 11), &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains("known_host = \"devbox\"") && !text.contains("host_keys"), "{text}");
        let line = report.lines.iter().find(|line| line.label == "known_hosts").unwrap();
        assert_eq!((line.status, line.hint.as_deref()), (Status::Ok, None));
    }

    /// Without a flag a pinned server keeps its keys, whatever known_hosts lists now, if
    /// ssh used one of them; else nothing is installed or written. `--pin` pins again
    /// from known_hosts, with a warning when keys go or come.
    #[test]
    fn pinned_servers_keep_their_keys() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut args = add_args("devbox", "build", &binary(dir.path()));
        args.pin = true;
        server_add_with(&ctx, &args, &shell_for(&ctx, "devbox", 7), &mut Report::default()).unwrap();
        let pinned = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(pinned.contains(&format!("host_keys = [\"{}\"]", test_key(7))), "{pinned}");

        // known_hosts gained a key: the pins stay, known_hosts is not even read.
        args.pin = false;
        let path = ctx.paths.home.join(".ssh/known_hosts");
        let shell = shell_for(&ctx, "devbox", 7);
        std::fs::write(&path, format!("devbox {}\ndevbox {}\n", test_key(7), test_key(8))).unwrap();
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), pinned);
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(
            (line.status, line.detail.as_str(), line.hint.as_deref()),
            (Status::Ok, "ssh-ed25519 (unchanged; --pin pins the keys known_hosts lists now)", None)
        );
        assert!(shell.commands().iter().any(|command| command.starts_with("install")));
        assert!(shell.commands().iter().any(|command| command.contains(" setup")));

        // ssh used a key that is not pinned: refused before anything is installed.
        let shell = shell_for(&ctx, "devbox", 9);
        let message =
            format!("{:#}", server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err());
        assert!(
            message.starts_with("the host key ssh used (ssh-ed25519 SHA256:")
                && message.ends_with(
                    ") is not pinned for devbox; check the host key change, then run server add devbox --pin"
                ),
            "{message}"
        );
        assert_eq!(shell.commands(), ["uname -sm"]);
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), pinned);

        // --pin: pinned again from known_hosts; keys replaced or added are a warning.
        args.pin = true;
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("host_keys = [\"{}\"]", test_key(9))), "{text}");
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(
            (line.status, line.hint.as_deref()),
            (Status::Warn, Some("the previously pinned keys were replaced"))
        );
        let shell = shell_for(&ctx, "devbox", 9);
        std::fs::write(&path, format!("devbox {}\ndevbox {}\n", test_key(9), test_key(10))).unwrap();
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("host_keys = [\"{}\", \"{}\"]", test_key(9), test_key(10))), "{text}");
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(
            (line.status, line.hint.as_deref()),
            (Status::Warn, Some("keys were pinned in addition to the previous ones"))
        );
    }

    /// `--pin` and `--follow` exclude each other.
    #[test]
    fn add_rejects_pin_with_follow() {
        use clap::Parser as _;
        let parsed = crate::cli::Cli::try_parse_from([
            "credential-bridge-ctl",
            "server",
            "add",
            "devbox",
            "--profile",
            "dev",
            "--pin",
            "--follow",
        ]);
        let error = parsed.unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict, "{error}");
    }

    /// known_hosts files other than OpenSSH's defaults are written, `~/` for the home.
    #[test]
    fn add_records_other_known_hosts_files() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let work = ctx.paths.home.join(".ssh/work_hosts");
        std::fs::create_dir_all(work.parent().unwrap()).unwrap();
        std::fs::write(&work, format!("[box.example]:2222 {}\n", test_key(5))).unwrap();
        let mut shell = shell_for(&ctx, "unused", 5);
        shell.ssh_g = format!(
            "hostname box.example\nport 2222\nuserknownhostsfile {}\nglobalknownhostsfile none\n",
            work.display()
        );
        server_add_with(&ctx, &add_args("box", "dev", &binary(dir.path())), &shell, &mut Report::default())
            .unwrap();
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(
            text.contains("[server.box]\nknown_host = \"[box.example]:2222\"\nknown_hosts_files = [\"~/.ssh/work_hosts\"]\n"),
            "{text}"
        );
        let config = load_config(&ctx).unwrap();
        let show = show_text(&ctx, &config, &config.servers["box"]);
        assert!(show.contains("host keys   known_hosts [box.example]:2222: ssh-ed25519\n            from ~/.ssh/work_hosts\n"), "{show}");
    }

    #[test]
    fn add_without_git_rules_skips_setup() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let shell = shell_for(&ctx, "devbox", 7);
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("devbox", "dev", &binary(dir.path())), &shell, &mut report).unwrap();
        assert!(!shell.commands().iter().any(|command| command.contains("setup")));
        let git = report.lines.iter().find(|line| line.label == "git config").unwrap();
        assert_eq!(git.detail, "nothing to set up");
    }

    #[test]
    fn add_fails_early() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let bin = binary(dir.path());
        let add = |shell: &FakeShell| {
            let error = server_add_with(&ctx, &add_args("b", "dev", &bin), shell, &mut Report::default());
            format!("{:#}", error.unwrap_err())
        };

        let error = server_add_with(&ctx, &add_args("b", "nope", &bin), &shell(&ctx), &mut Report::default());
        assert!(format!("{:#}", error.unwrap_err()).contains("profile \"nope\" does not exist"));

        // known_hosts lists nothing for the server, nor the key ssh used.
        let mut unknown = shell_for(&ctx, "b", 1);
        unknown.ssh_g = ssh_g(&ctx, "elsewhere");
        unknown.host_key = Some(test_key(3));
        let message = add(&unknown);
        assert!(message.starts_with("known_hosts has no host key for elsewhere (looked in "), "{message}");
        assert!(message.contains("connect once with `ssh b` and confirm the host key"), "{message}");

        // known_hosts lists the key ssh used under another name only.
        unknown.host_key = Some(test_key(1));
        let message = add(&unknown);
        assert!(message.contains("only under a pattern or another name, not under elsewhere"), "{message}");
        assert!(message.contains("--pin"), "{message}");

        // ssh used a key known_hosts does not list for it.
        let mut other = shell_for(&ctx, "b", 1);
        other.host_key = Some(test_key(2));
        let message = add(&other);
        assert!(message.starts_with("ssh b used the host key ssh-ed25519 SHA256:"), "{message}");
        assert!(
            message.contains("known_hosts lists other keys for b")
                && message.contains("would not recognise b"),
            "{message}"
        );

        // ssh named no host key.
        let mut silent = shell_for(&ctx, "b", 1);
        silent.host_key = None;
        assert!(add(&silent).contains("cannot tell which host key ssh used for b"));

        let mac = FakeShell::default().answer("uname", 0, "Darwin arm64\n");
        assert!(add(&mac).contains("only Linux"));

        let down = FakeShell::default().answer("uname", 255, "");
        assert!(add(&down).contains("cannot reach b"));

        // A relative or unexpanded known_hosts file in ssh -G: refused before anything
        // is installed.
        for (line, why) in [
            ("userknownhostsfile known_hosts\n", "is a relative path"),
            ("userknownhostsfile %d/known_hosts\n", "holds a % token"),
        ] {
            let mut relative = shell_for(&ctx, "b", 1);
            relative.ssh_g = format!("hostname b\nport 22\n{line}");
            let message = add(&relative);
            assert!(message.contains(why), "{message}");
            assert_eq!(relative.commands(), ["uname -sm"]);
        }

        // Nothing was written, nothing installed.
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), CONFIG);
        assert!(!other.commands().iter().any(|command| command.starts_with("install")));
    }

    /// A host key of the new server that another server has would make both
    /// unregistered: refused before anything is installed or written, on a dry run too.
    #[test]
    fn add_refuses_keys_of_another_server() {
        let (dir, ctx) = context();
        let bin = binary(dir.path());
        let pinned =
            format!("{CONFIG}\n[server.old]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n", test_key(7));
        write_config(&ctx, &pinned);
        let shell = shell_for(&ctx, "new", 7);
        let mut args = add_args("new", "dev", &bin);
        for dry_run in [false, true] {
            args.dry_run = dry_run;
            let message =
                format!("{:#}", server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err());
            assert!(
                message.starts_with("the host keys of new must be its own: ssh-ed25519 SHA256:"),
                "{message}"
            );
            assert!(message.contains(" also belongs to server old. "), "{message}");
            assert!(message.contains("nothing was installed or written"), "{message}");
        }
        // Pinned twice: the entry would not validate.
        args.pin = true;
        args.dry_run = false;
        let message =
            format!("{:#}", server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err());
        assert!(
            message.starts_with("[server.new] would not be accepted; nothing was installed"),
            "{message}"
        );
        assert!(message.contains("server.old.host_keys: host key SHA256:"), "{message}");
        assert!(message.contains("is also pinned for server \"new\""), "{message}");
        assert!(
            !shell.commands().iter().any(|command| command.starts_with("install")),
            "{:?}",
            shell.commands()
        );
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), pinned);

        // A followed server whose known_hosts lists the key under its own name.
        let followed = format!("{CONFIG}\n[server.old]\nknown_host = \"old\"\nprofile = \"dev\"\n");
        write_config(&ctx, &followed);
        known_host(&ctx, "old", &test_key(7));
        args.pin = false;
        let message =
            format!("{:#}", server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err());
        assert!(message.contains(" also belongs to server old. "), "{message}");
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), followed);
    }

    /// Where ssh "found" the host key or its CA: `~/.ssh/known_hosts` of the test home.
    fn found_in_known_hosts(ctx: &Context, authority: bool) -> Option<KnownHostsMatch> {
        Some(KnownHostsMatch { authority, file: ctx.paths.home.join(".ssh/known_hosts") })
    }

    /// A host ssh trusts through a wildcard line: following needs an exact entry, --pin
    /// takes the key ssh used from that line.
    #[test]
    fn add_pins_a_key_known_by_pattern() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut shell = shell_for(&ctx, "*.example.com", 5);
        shell.ssh_g = ssh_g(&ctx, "box.example.com");
        shell.host_key_verified = found_in_known_hosts(&ctx, false);
        let mut args = add_args("box", "dev", &binary(dir.path()));
        let message =
            format!("{:#}", server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err());
        assert!(
            message.contains("only under a pattern or another name, not under box.example.com"),
            "{message}"
        );
        args.pin = true;
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(
            line.detail,
            "ssh-ed25519 (the key ssh used; known_hosts lists it, but not under box.example.com)"
        );
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("[server.box]\nhost_keys = [\"{}\"]\n", test_key(5))), "{text}");
    }

    /// --pin needs ssh to have verified the key against a known_hosts file read here:
    /// a key ssh accepted without (StrictHostKeyChecking=no), or found in a file not
    /// read, or a certificate whose CA it did not find, is never pinned.
    #[test]
    fn add_pins_only_what_ssh_verified() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut args = add_args("box", "dev", &binary(dir.path()));
        args.pin = true;
        let refused = |shell: &FakeShell| {
            let message = format!(
                "{:#}",
                add_with(&ctx, &args, shell, &mut Report::default(), Duration::ZERO).unwrap_err()
            );
            assert!(
                message.starts_with("ssh did not verify the host key of box (ssh-ed25519 SHA256:"),
                "{message}"
            );
            assert!(
                message.contains(
                    "against known_hosts (StrictHostKeyChecking=no?), so nothing was pinned; connect once with \
                     host key checking on, then run server add again"
                ),
                "{message}"
            );
            assert!(!shell.commands().iter().any(|command| command.starts_with("install")));
        };

        // known_hosts lists the key under another host's name only; ssh accepted it.
        let mut shell = shell_for(&ctx, "other", 5);
        shell.ssh_g = ssh_g(&ctx, "box.example.com");
        refused(&shell);
        // ssh names a file it did not read (or one ctl did not read).
        shell.host_key_verified = Some(KnownHostsMatch { authority: false, file: "/elsewhere".into() });
        refused(&shell);
        // A CA line does not vouch for a plain key.
        shell.host_key_verified = found_in_known_hosts(&ctx, true);
        refused(&shell);

        // A certificate: only a CA ssh found counts.
        let path = ctx.paths.home.join(".ssh/known_hosts");
        std::fs::write(&path, format!("@cert-authority *.example.com {}\n", test_key(9))).unwrap();
        let mut shell = shell_for(&ctx, "unused", 6);
        std::fs::write(&path, format!("@cert-authority *.example.com {}\n", test_key(9))).unwrap();
        shell.host_certificate = true;
        shell.ssh_g = ssh_g(&ctx, "box.example.com");
        refused(&shell);
        assert!(!shell.commands().iter().any(|command| command.starts_with("ssh-keyscan")));

        // A certificate whose CA ssh did not know, while known_hosts vouches for the
        // plain key through a pattern: the plain key is pinned, nothing is scanned.
        std::fs::write(&path, format!("*.example.com {}\n", test_key(6))).unwrap();
        shell.host_key_verified = found_in_known_hosts(&ctx, false);
        let mut report = Report::default();
        add_with(&ctx, &args, &shell, &mut report, Duration::ZERO).unwrap();
        assert!(!shell.commands().iter().any(|command| command.starts_with("ssh-keyscan")));
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("[server.box]\nhost_keys = [\"{}\"]\n", test_key(6))), "{text}");
    }

    /// A host that shows a host certificate signed by a trusted CA: --pin pins the key in
    /// the certificate, taken from ssh-keyscan and checked against ssh's fingerprint.
    #[test]
    fn add_pins_the_key_in_a_host_certificate() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let path = ctx.paths.home.join(".ssh/known_hosts");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("@cert-authority *.example.com {}\n", test_key(9))).unwrap();
        let cert_shell = || {
            let mut shell = shell_for(&ctx, "unused", 6);
            std::fs::write(&path, format!("@cert-authority *.example.com {}\n", test_key(9))).unwrap();
            shell.host_certificate = true;
            shell.host_key_verified = found_in_known_hosts(&ctx, true);
            shell.ssh_g = ssh_g(&ctx, "box.example.com");
            shell
        };
        let mut args = add_args("box", "dev", &binary(dir.path()));
        let add = |shell: &FakeShell, args: &ServerAddArgs, report: &mut Report| {
            add_with(&ctx, args, shell, report, Duration::ZERO)
        };

        let shell = cert_shell();
        let message = format!("{:#}", add(&shell, &args, &mut Report::default()).unwrap_err());
        assert!(
            message.starts_with("ssh box trusts the host certificate of ssh-ed25519 SHA256:"),
            "{message}"
        );
        assert!(message.contains("Run this again with --pin"), "{message}");

        // The first scan comes back empty (PerSourcePenalties), the second has the key.
        args.pin = true;
        let shell = cert_shell();
        *shell.keyscans.borrow_mut() = vec![
            String::new(),
            format!("# box.example.com:22 SSH-2.0-OpenSSH_10.2\nbox.example.com {}\n", test_key(6)),
        ];
        let mut report = Report::default();
        add(&shell, &args, &mut report).unwrap();
        let scans: Vec<String> =
            shell.commands().into_iter().filter(|command| command.starts_with("ssh-keyscan")).collect();
        assert_eq!(scans, ["ssh-keyscan -t ed25519 -p 22"; 2]);
        assert!(
            report.lines[0].detail.ends_with("(used by ssh, host certificate)"),
            "{}",
            report.lines[0].detail
        );
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!(line.detail, "ssh-ed25519 (the key in the host certificate, checked with ssh-keyscan)");
        let text = std::fs::read_to_string(&ctx.config_path).unwrap();
        assert!(text.contains(&format!("[server.box]\nhost_keys = [\"{}\"]\n", test_key(6))), "{text}");

        // Run again without a flag: the server keeps its pinned key, nothing is scanned.
        args.pin = false;
        let shell = cert_shell();
        let mut report = Report::default();
        add(&shell, &args, &mut report).unwrap();
        assert!(!shell.commands().iter().any(|command| command.starts_with("ssh-keyscan")));
        let line = report.lines.iter().find(|line| line.label == "host keys pinned").unwrap();
        assert_eq!((line.status, line.hint.as_deref()), (Status::Ok, None));
        assert!(line.detail.starts_with("ssh-ed25519 (unchanged"), "{}", line.detail);
        assert_eq!(text, std::fs::read_to_string(&ctx.config_path).unwrap());
        // ... unless the certificate holds another key now.
        let mut shell = cert_shell();
        shell.host_key = Some(test_key(8));
        let message = format!("{:#}", add(&shell, &args, &mut Report::default()).unwrap_err());
        assert!(message.contains("is not pinned for box; check the host key change"), "{message}");
        assert!(!shell.commands().iter().any(|command| command.starts_with("install")));
        args.pin = true;

        // A scan with another key is never pinned; no answer at all neither.
        let shell = cert_shell();
        *shell.keyscans.borrow_mut() = vec![format!("box.example.com {}\n", test_key(8)); 3];
        let message = format!("{:#}", add(&shell, &args, &mut Report::default()).unwrap_err());
        assert!(
            message.starts_with("ssh-keyscan -t ed25519 -p 22 box.example.com returned ssh-ed25519 SHA256:"),
            "{message}"
        );
        assert!(message.contains("not the key in the host certificate ssh box used"), "{message}");
        let shell = cert_shell();
        let message = format!("{:#}", add(&shell, &args, &mut Report::default()).unwrap_err());
        assert!(message.contains("returned no key in 3 attempts"), "{message}");
        assert!(text == std::fs::read_to_string(&ctx.config_path).unwrap());

        // A certificate whose key known_hosts also lists under the exact name: followed.
        let mut shell = shell_for(&ctx, "box.example.com", 6);
        shell.host_certificate = true;
        (args.pin, args.follow) = (false, true);
        add(&shell, &args, &mut Report::default()).unwrap();
        assert!(
            std::fs::read_to_string(&ctx.config_path).unwrap().contains("known_host = \"box.example.com\"")
        );
        assert!(!shell.commands().iter().any(|command| command.starts_with("ssh-keyscan")));
    }

    /// An unreadable known_hosts file is skipped with a warning, as ssh skips it.
    #[test]
    fn add_skips_unreadable_known_hosts_files() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let shell = shell_for(&ctx, "devbox", 7);
        let second = ctx.paths.home.join(".ssh/known_hosts2");
        std::fs::create_dir_all(&second).unwrap();
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("devbox", "dev", &binary(dir.path())), &shell, &mut report).unwrap();
        let line = report.lines.iter().find(|line| line.label == "known_hosts file").unwrap();
        assert_eq!(line.status, Status::Warn);
        assert_eq!(
            line.detail,
            format!(
                "cannot read {}: not a regular file; skipped (ssh and the daemon skip it too)",
                second.display()
            )
        );
    }

    /// Without UpdateHostKeys ssh learns no new host keys: a hint for a followed server.
    /// The known_hosts name is written lowercase, as ssh looks it up.
    #[test]
    fn add_hints_when_ssh_does_not_update_host_keys() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut shell = shell_for(&ctx, "devbox", 7);
        shell.ssh_g = ssh_g(&ctx, "DevBox").replace("port 22\n", "port 22\nupdatehostkeys false\n");
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("devbox", "dev", &binary(dir.path())), &shell, &mut report).unwrap();
        let line = report.lines.iter().find(|line| line.label == "known_hosts").unwrap();
        assert_eq!(line.status, Status::Ok);
        assert!(
            line.hint.as_deref().unwrap().starts_with("ssh does not learn new host keys of devbox"),
            "{line:?}"
        );
        assert!(std::fs::read_to_string(&ctx.config_path).unwrap().contains("known_host = \"devbox\"\n"));
    }

    #[test]
    fn add_warns_without_forward_agent() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut shell = shell_for(&ctx, "devbox", 7);
        shell.ssh_g = ssh_g(&ctx, "devbox").replace("forwardagent ", "forwardagent no\n#");
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("devbox", "dev", &binary(dir.path())), &shell, &mut report).unwrap();
        let last = report.lines.iter().find(|line| line.label == "ssh config").unwrap();
        assert_eq!(
            last.to_string(),
            "⚠ ssh config           no ForwardAgent to the proxy for devbox\n                       → credential-bridge-ctl server ssh-config devbox"
        );
    }

    #[test]
    fn add_warns_about_an_old_ssh_client() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let mut shell = shell_for(&ctx, "devbox", 7);
        shell.ssh_version = Some("OpenSSH_8.8p1, OpenSSL 1.1.1l  24 Aug 2021\n".into());
        let mut report = Report::default();
        server_add_with(&ctx, &add_args("devbox", "dev", &binary(dir.path())), &shell, &mut report).unwrap();
        let last = report.lines.iter().find(|line| line.label == "ssh client").unwrap();
        assert_eq!(
            last.to_string(),
            "⚠ ssh client           OpenSSH 8.8 sends no session-bind: servers are not recognised: no keys, no tokens, no gpg\n                       → OpenSSH 8.9 or later is needed to recognise servers"
        );
    }

    #[test]
    fn ssh_client_lines() {
        let line = |version: &str| {
            let shell = FakeShell { ssh_version: Some(version.into()), ..FakeShell::default() };
            ssh_client_line(&shell)
        };
        let ok = line("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022\n");
        assert_eq!((ok.status, ok.detail.as_str()), (Status::Ok, "OpenSSH 8.9"));
        assert_eq!(line("OpenSSH_10.0p2, OpenSSL 3.5.0\n").status, Status::Ok);
        assert_eq!(line("OpenSSH_8.8p1, OpenSSL 1.1.1l\n").status, Status::Warn);
        let other = line("Dropbear v2022.83\n");
        assert_eq!(other.status, Status::Warn);
        assert!(other.detail.starts_with("not OpenSSH (Dropbear v2022.83): "), "{}", other.detail);
    }

    /// A known_hosts file that cannot be read shows in list and show of the servers that
    /// follow it, and server add warns that keys in it are not compared.
    #[test]
    fn unreadable_known_hosts_files_are_shown() {
        let (dir, ctx) = context();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let with = format!(
            "{CONFIG}\n[server.old]\nknown_host = \"old\"\nknown_hosts_files = [\"{}\"]\nprofile = \"dev\"\n",
            locked.display()
        );
        write_config(&ctx, &with);
        let config = load_config(&ctx).unwrap();
        let list = list_text(&config);
        assert!(
            list.contains(&format!(
                "old     dev      known_hosts old: none  [cannot read {}]\n",
                locked.display()
            )),
            "{list}"
        );
        let show = show_text(&ctx, &config, &config.servers["old"]);
        assert!(
            show.contains(&format!(
                "            cannot read {}: not a regular file; skipped (ssh and the daemon skip it too)\n\
                 \x20           known_hosts lists no key for old: the server is treated as unregistered\n",
                locked.display()
            )),
            "{show}"
        );

        let mut report = Report::default();
        server_add_with(
            &ctx,
            &add_args("devbox", "dev", &binary(dir.path())),
            &shell_for(&ctx, "devbox", 7),
            &mut report,
        )
        .unwrap();
        let line = report.lines.iter().find(|line| line.label == "known_hosts file").unwrap();
        assert_eq!(line.status, Status::Warn);
        assert!(line.detail.starts_with(&format!("cannot read {}: ", locked.display())), "{}", line.detail);
        assert_eq!(line.hint.as_deref(), Some("keys in it are not compared with the new server's"));
    }

    #[test]
    fn list_show_and_remove() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let bin = binary(dir.path());
        server_add_with(&ctx, &add_args("buildserver", "build", &bin), &shell(&ctx), &mut Report::default())
            .unwrap();
        let mut pin = add_args("devbox", "dev", &bin);
        pin.pin = true;
        server_add_with(&ctx, &pin, &shell_for(&ctx, "devbox", 8), &mut Report::default()).unwrap();
        let config = load_config(&ctx).unwrap();

        let list = list_text(&config);
        assert_eq!(
            list,
            "SERVER       PROFILE  HOST KEYS\nbuildserver  build    known_hosts buildserver: ssh-ed25519\n\
             devbox       dev      pinned: ssh-ed25519\n"
        );

        let show = show_text(&ctx, &config, &config.servers["buildserver"]);
        assert!(
            show.contains(
                "host keys   known_hosts buildserver: ssh-ed25519\n            ssh-ed25519 SHA256:"
            ),
            "{show}"
        );
        assert!(show.contains("git         https://github.com/my-org/* -> github (github (gh))"), "{show}");
        assert!(show.contains("hops        ssh"));
        let show = show_text(&ctx, &config, &config.servers["devbox"]);
        assert!(show.contains("host keys   pinned: ssh-ed25519\n            ssh-ed25519 SHA256:"), "{show}");
        assert!(
            show.contains("ssh         all keys (no [agent]: none), confirm each use (remembered 8h)"),
            "{show}"
        );

        let shell = shell_for(&ctx, "devbox", 8);
        let args = ServerRemoveArgs { name: "devbox".into(), remote: true, dry_run: false };
        server_remove_with(&ctx, &args, &shell, &mut Report::default()).unwrap();
        assert_eq!(shell.commands(), vec![format!("{REMOTE_BINARY} uninstall --remove-binary")]);
        let config = load_config(&ctx).unwrap();
        assert!(!config.servers.contains_key("devbox"));
        assert!(config.servers.contains_key("buildserver"));

        let error = server_remove_with(&ctx, &args, &shell, &mut Report::default()).unwrap_err();
        assert!(error.to_string().contains("no [server.devbox]"));
        assert!(std::fs::read_to_string(&ctx.config_path).unwrap().contains("# the build profile"));
    }

    #[test]
    fn failed_remote_cleanup_keeps_the_entry() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        server_add_with(
            &ctx,
            &add_args("devbox", "dev", &binary(dir.path())),
            &shell_for(&ctx, "devbox", 7),
            &mut Report::default(),
        )
        .unwrap();
        let broken = FakeShell::default().answer(REMOTE_BINARY, 255, "");
        let args = ServerRemoveArgs { name: "devbox".into(), remote: true, dry_run: false };
        assert!(server_remove_with(&ctx, &args, &broken, &mut Report::default()).is_err());
        assert!(load_config(&ctx).unwrap().servers.contains_key("devbox"));
    }

    /// `server remove` needs the entry in the file, checked in the file before ssh runs:
    /// a file that does not parse is not a reason to go ahead.
    #[test]
    fn remove_checks_the_entry_before_touching_the_server() {
        let (_dir, ctx) = context();
        let shell = shell(&ctx).answer(REMOTE_BINARY, 0, "");
        let remove = |name: &str, remote| ServerRemoveArgs { name: name.into(), remote, dry_run: false };
        write_config(&ctx, "version = \n[server.box]\n");
        for name in ["box", "nope"] {
            let error =
                server_remove_with(&ctx, &remove(name, true), &shell, &mut Report::default()).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.starts_with("cannot tell whether [server."), "{message}");
            assert!(message.contains(&format!("credential-bridge-ctl server uninstall {name}")), "{message}");
        }
        assert!(shell.commands().is_empty(), "{:?}", shell.commands());

        // An invalid file that names the server: it is cleaned up and removed, which
        // here also makes the file valid again.
        let invalid = "version = 2\n[server.box]\nhost_keys = []\nprofile = \"nope\"\n";
        write_config(&ctx, invalid);
        let message = server_remove_with(&ctx, &remove("nope", true), &shell, &mut Report::default())
            .unwrap_err()
            .to_string();
        assert!(message.starts_with("no [server.nope] in "), "{message}");
        assert!(shell.commands().is_empty(), "{:?}", shell.commands());
        server_remove_with(&ctx, &remove("box", true), &shell, &mut Report::default()).unwrap();
        assert_eq!(shell.commands(), [format!("{REMOTE_BINARY} uninstall --remove-binary")]);
        assert!(load_config(&ctx).unwrap().servers.is_empty());

        // Missing file, missing entry: the same, with the uninstall hint.
        std::fs::remove_file(&ctx.config_path).unwrap();
        let message = server_remove_with(&ctx, &remove("box", true), &shell, &mut Report::default())
            .unwrap_err()
            .to_string();
        assert!(
            message.starts_with("no [server.box] in ") && message.contains("server uninstall box"),
            "{message}"
        );
        assert_eq!(shell.commands().len(), 1);
    }

    /// Without --remote the server is left alone, and the report says how to clean it up.
    #[test]
    fn remove_without_remote_hints_at_uninstall() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        server_add_with(
            &ctx,
            &add_args("devbox", "dev", &binary(dir.path())),
            &shell_for(&ctx, "devbox", 7),
            &mut Report::default(),
        )
        .unwrap();
        let shell = FakeShell::default();
        let mut report = Report::default();
        let args = ServerRemoveArgs { name: "devbox".into(), remote: false, dry_run: false };
        server_remove_with(&ctx, &args, &shell, &mut report).unwrap();
        assert!(shell.commands().is_empty());
        assert!(!load_config(&ctx).unwrap().servers.contains_key("devbox"));
        let last = report.lines.last().unwrap().to_string();
        assert!(last.contains("devbox keeps credential-bridge-remote"), "{last}");
        assert!(last.contains("→ to remove them: credential-bridge-ctl server uninstall devbox"), "{last}");
    }

    #[test]
    fn uninstall_runs_only_on_the_server() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        server_add_with(
            &ctx,
            &add_args("devbox", "dev", &binary(dir.path())),
            &shell_for(&ctx, "devbox", 7),
            &mut Report::default(),
        )
        .unwrap();
        let before = std::fs::read_to_string(&ctx.config_path).unwrap();
        let uninstall = |dest: &str, dry_run| ServerUninstallArgs { dest: dest.into(), dry_run };

        // Dry run: nothing runs.
        let shell = FakeShell::default();
        let mut report = Report::default();
        server_uninstall_with(&ctx, &uninstall("me@old", true), &shell, &mut report).unwrap();
        assert!(shell.commands().is_empty());
        assert!(
            report.text.contains(&format!("would run `{REMOTE_BINARY} uninstall --remove-binary` on me@old")),
            "{}",
            report.text
        );

        // Any destination, registered or not; the configuration stays as it is.
        let shell = FakeShell::default().answer(REMOTE_BINARY, 0, "");
        for dest in ["devbox", "me@old"] {
            server_uninstall_with(&ctx, &uninstall(dest, false), &shell, &mut Report::default()).unwrap();
        }
        assert_eq!(
            *shell.calls.borrow(),
            ["devbox", "me@old"]
                .map(|dest| (dest.to_owned(), format!("{REMOTE_BINARY} uninstall --remove-binary")))
        );
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), before);

        // A failure explains the missing keys only for hosts without an entry.
        let broken = FakeShell::default().answer(REMOTE_BINARY, 255, "");
        let message =
            server_uninstall_with(&ctx, &uninstall("me@old", false), &broken, &mut Report::default())
                .unwrap_err()
                .to_string();
        assert!(message.starts_with("me@old was not cleaned up. It is not a registered server"), "{message}");
        assert!(message.contains("profile.unregistered") && message.contains("own key file"), "{message}");
        assert!(message.contains("server add me@old --profile PROFILE"), "{message}");
        assert!(message.contains("server remove me@old --remote"), "{message}");
        let message =
            server_uninstall_with(&ctx, &uninstall("devbox", false), &broken, &mut Report::default())
                .unwrap_err()
                .to_string();
        assert_eq!(message, "devbox was not cleaned up");
        write_config(&ctx, "version = \n");
        let message =
            server_uninstall_with(&ctx, &uninstall("devbox", false), &broken, &mut Report::default())
                .unwrap_err()
                .to_string();
        assert!(
            message.contains("If it is not a registered server, the bridge gives it no keys"),
            "{message}"
        );
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), "version = \n");
    }

    #[test]
    fn add_and_remove_dry_run_touch_nothing() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let shell = shell(&ctx);
        let mut args = add_args("buildserver", "build", &binary(dir.path()));
        args.dry_run = true;
        let mut report = Report::default();
        server_add_with(&ctx, &args, &shell, &mut report).unwrap();
        assert_eq!(shell.commands(), vec!["uname -sm".to_owned()]);
        assert!(
            report.text.contains("+[server.buildserver]\n+known_host = \"buildserver\"\n"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("✓ dry run              nothing installed on buildserver"),
            "{}",
            report.text
        );
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), CONFIG);

        args.dry_run = false;
        server_add_with(&ctx, &args, &shell, &mut Report::default()).unwrap();
        let before = std::fs::read_to_string(&ctx.config_path).unwrap();
        let remove = ServerRemoveArgs { name: "buildserver".into(), remote: true, dry_run: true };
        let shell = FakeShell::default();
        let mut report = Report::default();
        server_remove_with(&ctx, &remove, &shell, &mut report).unwrap();
        assert!(shell.commands().is_empty());
        assert!(report.text.contains("-[server.buildserver]\n"), "{}", report.text);
        assert_eq!(std::fs::read_to_string(&ctx.config_path).unwrap(), before);
        let missing = ServerRemoveArgs { name: "nope".into(), remote: false, dry_run: true };
        assert!(
            server_remove_with(&ctx, &missing, &shell, &mut report)
                .unwrap_err()
                .to_string()
                .contains("no [server.nope]")
        );
    }

    #[test]
    fn set_changes_the_profile_and_hints_at_the_git_config() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        server_add_with(
            &ctx,
            &add_args("box", "build", &binary(dir.path())),
            &shell_for(&ctx, "box", 7),
            &mut Report::default(),
        )
        .unwrap();
        let set = |profile: &str, dry_run| ServerSetArgs {
            name: "box".into(),
            profile: profile.into(),
            write: crate::cli::WriteArgs { dry_run },
        };
        let mut report = Report::default();
        let message = format!("{:#}", server_set(&ctx, &set("nope", false), &mut report).unwrap_err());
        assert!(message.contains("\"nope\" is not a [profile.*] name"), "{message}");
        let message =
            format!("{:#}", server_set(&ctx, &set("unregistered", false), &mut report).unwrap_err());
        assert!(message.contains("give the server a profile of its own"), "{message}");
        server_set(&ctx, &set("dev", false), &mut report).unwrap();
        assert_eq!(load_config(&ctx).unwrap().servers["box"].profile, "dev");
        let hint = report.lines.last().unwrap().to_string();
        assert!(hint.contains("credential-bridge-ctl server add box --profile dev"), "{hint}");
        let mut report = Report::default();
        server_set(&ctx, &set("dev", false), &mut report).unwrap();
        assert!(report.text.contains("unchanged"), "{}", report.text);
    }

    #[test]
    fn setup_arguments() {
        let hosts = vec![("github.com".to_owned(), true), ("git.example.com:8443".to_owned(), false)];
        assert_eq!(
            setup_argv(&hosts, Some("ssh-ed25519 AAAA"), true),
            vec![
                REMOTE_BINARY,
                "setup",
                "--host",
                "github.com",
                "--host",
                "git.example.com:8443",
                "--http-path",
                "github.com",
                "--signing-key",
                "ssh-ed25519 AAAA",
                "--print"
            ]
        );
    }

    #[test]
    fn ssh_config_output() {
        let (dir, ctx) = context();
        write_config(&ctx, CONFIG);
        let bin = binary(dir.path());
        server_add_with(&ctx, &add_args("buildserver", "build", &bin), &shell(&ctx), &mut Report::default())
            .unwrap();
        server_add_with(
            &ctx,
            &add_args("devbox", "dev", &bin),
            &shell_for(&ctx, "devbox", 8),
            &mut Report::default(),
        )
        .unwrap();
        let config = load_config(&ctx).unwrap();

        let both =
            ssh_config_text(&ctx, &config, &SshConfigArgs { servers: vec![], fallback: None }).unwrap();
        assert!(both.contains(
            "Host *\n  IdentityAgent ~/.local/state/credential-bridge/agent.sock\n\n\
             Host buildserver devbox\n  ForwardAgent ~/.local/state/credential-bridge/agent-forward.sock\n"
        ));
        assert!(
            both.contains(
                "Match originalhost buildserver,devbox exec \"credential-bridge-ctl daemon alive\""
            )
        );
        assert!(both.contains("IdentityAgent FALLBACK_AGENT_SOCKET"));

        let args = SshConfigArgs {
            servers: vec!["devbox".into()],
            fallback: Some(PathBuf::from("~/.1password/agent.sock")),
        };
        let fallback = ssh_config_text(&ctx, &config, &args).unwrap();
        assert!(fallback.contains("Match originalhost devbox exec"));
        assert!(fallback.contains("Host *\n  IdentityAgent ~/.1password/agent.sock\n"));
        assert!(!fallback.contains("Variant 1"));

        let args = SshConfigArgs { servers: vec!["unknown".into()], fallback: None };
        assert!(ssh_config_text(&ctx, &config, &args).is_err());
    }
}
