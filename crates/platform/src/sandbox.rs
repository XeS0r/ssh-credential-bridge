//! Worker sandboxes (security rule 8).
//!
//! Linux: `no_new_privs`, Landlock (file system; network rules from kernel 6.7 / ABI 4),
//! seccomp. macOS: one sandbox profile per worker. A layer the kernel lacks is skipped
//! and reported in [`SandboxReport::missing`]; the worker still runs, and the core logs
//! it. Sandboxes are inherited by child processes, which is why only workers that never
//! start programs are sandboxed.

use std::path::{Path, PathBuf};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")
))]
mod seccomp;

/// No seccomp filters on other architectures (`seccompiler` supports these three).
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))
))]
mod seccomp {
    /// Never constructed.
    #[derive(Debug)]
    pub(super) enum Programs {}

    #[derive(Debug)]
    pub(super) struct Unsupported;

    pub(super) fn programs(_profile: super::SyscallProfile) -> Result<Programs, Unsupported> {
        Err(Unsupported)
    }

    pub(super) fn install(programs: &Programs) -> Result<(), String> {
        match *programs {}
    }
}

/// Which system call allowlist to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallProfile {
    /// The git worker: tokio, rustls, DNS resolution, TCP client sockets.
    NetworkClient,
    /// The gpg worker: reading and writing descriptors it was handed, receiving
    /// descriptors over its channel; no `socket`, `connect` or `open`.
    DescriptorRelay,
}

/// What a sandboxed worker may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// Files and directories readable (recursively); nothing is writable.
    pub read_paths: Vec<PathBuf>,
    /// TCP ports `connect` may reach (Landlock restricts ports, not hosts). Empty: no
    /// TCP at all.
    pub tcp_connect_ports: Vec<u16>,
    /// The system call allowlist.
    pub syscalls: SyscallProfile,
}

impl SandboxSpec {
    /// The git worker: TCP port 443, read-only DNS files (`/etc/resolv.conf`,
    /// `/etc/hosts`, `/etc/nsswitch.conf`, …) and the system CA store.
    ///
    /// Only paths that exist are listed; symlinks (`/etc/resolv.conf` →
    /// `/run/systemd/resolve/…`, `/etc/ssl` → `/nix/store/…`) are listed together with
    /// their targets, because the sandbox checks the resolved path. `SSL_CERT_FILE`,
    /// `SSL_CERT_DIR` and `NIX_SSL_CERT_FILE` are added if set in the worker's
    /// environment. Call it before [`apply`]: it reads the file system.
    pub fn git_worker() -> SandboxSpec {
        let env: Vec<PathBuf> = ["SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE"]
            .into_iter()
            .filter_map(std::env::var_os)
            .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
            .filter(|p| p.is_absolute())
            .collect();
        let candidates = GIT_READ_PATHS.iter().map(PathBuf::from).chain(env);
        SandboxSpec {
            read_paths: existing_with_targets(candidates),
            tcp_connect_ports: vec![443],
            syscalls: SyscallProfile::NetworkClient,
        }
    }

    /// The gpg worker: no file system, no network; descriptors come from the core.
    pub fn gpg_worker() -> SandboxSpec {
        SandboxSpec {
            read_paths: Vec::new(),
            tcp_connect_ports: Vec::new(),
            syscalls: SyscallProfile::DescriptorRelay,
        }
    }
}

/// Where name resolution and the CA store live on Linux and macOS distributions.
/// Library directories are listed because glibc loads NSS modules on demand.
const GIT_READ_PATHS: &[&str] = &[
    // Name resolution.
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
    "/etc/ld.so.cache",
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/var/run/resolv.conf",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    // CA stores (Debian, Fedora, Arch, openSUSE, Alpine, NixOS, macOS).
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/usr/share/ca-certificates",
    "/usr/local/share/ca-certificates",
    "/usr/share/pki",
    "/var/lib/ca-certificates",
    // macOS trust settings and keychains read by Security.framework.
    "/System/Library/Keychains",
    "/Library/Keychains",
    "/System/Library/Security",
    "/private/var/db/mds/system",
];

/// The paths of `candidates` that exist, each followed by its resolved target when
/// that differs, without duplicates and in order.
fn existing_with_targets(candidates: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    for path in candidates {
        let Ok(target) = std::fs::canonicalize(&path) else { continue };
        if target != path {
            push(path);
        }
        push(target);
    }
    out
}

/// One sandbox mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// Landlock file system rules.
    LandlockFs,
    /// Landlock network rules.
    LandlockNet,
    /// seccomp-bpf system call filter.
    Seccomp,
    /// macOS sandbox profile.
    MacosProfile,
}

/// What [`apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxReport {
    /// Layers in force.
    pub applied: Vec<Layer>,
    /// Layers skipped because the system lacks them, with the reason.
    pub missing: Vec<(Layer, String)>,
}

/// A layer that the system supports could not be applied; the worker must exit.
#[derive(Debug, thiserror::Error)]
#[error("sandbox layer {layer:?} failed: {message}")]
pub struct SandboxError {
    /// The layer.
    pub layer: Layer,
    /// What failed.
    pub message: String,
}

/// Applies `spec` to the calling process (all threads that exist later; call before the
/// tokio runtime starts). Irreversible.
///
/// Linux order: `no_new_privs`, Landlock file system rules and scopes, Landlock network
/// rules, then the seccomp filters (which forbid `execve`, `ptrace`, `kill` and, for
/// [`SyscallProfile::DescriptorRelay`], `open`/`socket`/`connect`). macOS: the profile
/// of [`SandboxSpec`] via `sandbox_init`; frameworks the worker needs later (Security,
/// for example) should be loaded before, since the profile denies reading most of the
/// file system.
pub fn apply(spec: &SandboxSpec) -> Result<SandboxReport, SandboxError> {
    imp::apply(spec)
}

#[cfg(target_os = "linux")]
mod imp {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, LandlockStatus, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetError, RulesetStatus, Scope, path_beneath_rules,
    };

    use super::{Layer, SandboxError, SandboxReport, SandboxSpec, seccomp};

    /// The newest Landlock ABI used: file system (1-3, 5), network (4), scopes (6).
    const ABI_FS: ABI = ABI::V6;
    const ABI_NET: ABI = ABI::V4;

    pub(super) fn apply(spec: &SandboxSpec) -> Result<SandboxReport, SandboxError> {
        let mut report = SandboxReport::default();

        rustix::thread::set_no_new_privs(true).map_err(|e| fail(Layer::NoNewPrivs, e))?;
        report.applied.push(Layer::NoNewPrivs);

        // Prepared while /proc is still readable.
        let seccomp = match (seccomp::programs(spec.syscalls), seccomp_in_kernel()) {
            (Ok(programs), true) => Some(programs),
            (Ok(_), false) => {
                report.missing.push((Layer::Seccomp, "the kernel has no seccomp support".to_owned()));
                None
            }
            (Err(seccomp::Unsupported), _) => {
                let arch = std::env::consts::ARCH;
                report.missing.push((Layer::Seccomp, format!("no system call filter for {arch}")));
                None
            }
        };

        match landlock_fs(spec).map_err(|e| fail(Layer::LandlockFs, e))? {
            Ok(()) => report.applied.push(Layer::LandlockFs),
            Err(reason) => report.missing.push((Layer::LandlockFs, reason)),
        }
        match landlock_net(spec).map_err(|e| fail(Layer::LandlockNet, e))? {
            Ok(()) => report.applied.push(Layer::LandlockNet),
            Err(reason) => report.missing.push((Layer::LandlockNet, reason)),
        }

        // Last: the filter does not allow the Landlock system calls.
        if let Some(programs) = seccomp {
            seccomp::install(&programs).map_err(|message| SandboxError { layer: Layer::Seccomp, message })?;
            report.applied.push(Layer::Seccomp);
        }
        Ok(report)
    }

    /// Read-only access to `read_paths`, nothing else; no abstract unix sockets or
    /// signals outside the sandbox (ABI 6). `Ok(Err(reason))`: Landlock is missing.
    fn landlock_fs(spec: &SandboxSpec) -> Result<Result<(), String>, RulesetError> {
        let read = AccessFs::ReadFile | AccessFs::ReadDir;
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI_FS))?
            .scope(Scope::from_all(ABI_FS))?
            .create()?
            .add_rules(path_beneath_rules(&spec.read_paths, read))?
            .restrict_self()?;
        Ok(match status.ruleset {
            RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Ok(()),
            RulesetStatus::NotEnforced => Err(missing_reason(&status.landlock, "Landlock")),
        })
    }

    /// TCP `connect` only to `tcp_connect_ports`, no TCP `bind` (ABI 4, Linux 6.7).
    fn landlock_net(spec: &SandboxSpec) -> Result<Result<(), String>, RulesetError> {
        let status = Ruleset::default()
            .handle_access(AccessNet::from_all(ABI_NET))?
            .create()?
            .add_rules(
                spec.tcp_connect_ports
                    .iter()
                    .map(|&port| Ok::<_, RulesetError>(NetPort::new(port, AccessNet::ConnectTcp))),
            )?
            .restrict_self()?;
        Ok(match status.ruleset {
            RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Ok(()),
            RulesetStatus::NotEnforced => {
                Err(missing_reason(&status.landlock, "Landlock network rules (Linux 6.7)"))
            }
        })
    }

    fn missing_reason(status: &LandlockStatus, what: &str) -> String {
        match status {
            LandlockStatus::NotEnabled => format!("{what}: Landlock is disabled in this kernel"),
            LandlockStatus::NotImplemented => format!("{what}: the kernel has no Landlock"),
            LandlockStatus::Available { effective_abi, .. } => {
                format!("{what}: not supported by Landlock ABI {}", *effective_abi as i32)
            }
        }
    }

    /// Whether the kernel knows seccomp (`Seccomp:` in `/proc/self/status`). Unknown
    /// counts as yes, so that installing the filter reports the real error.
    fn seccomp_in_kernel() -> bool {
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => status.lines().any(|line| line.starts_with("Seccomp:")),
            Err(_) => true,
        }
    }

    fn fail(layer: Layer, error: impl std::fmt::Display) -> SandboxError {
        SandboxError { layer, message: error.to_string() }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{Layer, SandboxError, SandboxReport, SandboxSpec};

    pub(super) fn apply(spec: &SandboxSpec) -> Result<SandboxReport, SandboxError> {
        crate::macos::apply_sandbox_profile(&super::macos_profile(spec))
            .map_err(|message| SandboxError { layer: Layer::MacosProfile, message })?;
        Ok(SandboxReport { applied: vec![Layer::MacosProfile], missing: Vec::new() })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::{Layer, SandboxError, SandboxReport, SandboxSpec};

    pub(super) fn apply(_spec: &SandboxSpec) -> Result<SandboxReport, SandboxError> {
        let reason = || "not available on this platform".to_owned();
        Ok(SandboxReport {
            applied: Vec::new(),
            missing: vec![
                (Layer::NoNewPrivs, reason()),
                (Layer::LandlockFs, reason()),
                (Layer::Seccomp, reason()),
            ],
        })
    }
}

/// The macOS sandbox profile (SBPL) for `spec`: deny by default, read `read_paths`,
/// TCP to `tcp_connect_ports`, and for [`SyscallProfile::NetworkClient`] the system
/// services name resolution and certificate checks talk to.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_profile(spec: &SandboxSpec) -> String {
    let mut profile = String::from("(version 1)\n(deny default)\n(import \"system.sb\")\n");
    if !spec.read_paths.is_empty() {
        profile.push_str("(allow file-read*");
        for path in &spec.read_paths {
            let Some(escaped) = sbpl_escape(path) else { continue };
            let kind = if path.is_dir() { "subpath" } else { "literal" };
            profile.push_str(&format!("\n    ({kind} \"{escaped}\")"));
        }
        profile.push_str(")\n");
    }
    for port in &spec.tcp_connect_ports {
        profile.push_str(&format!("(allow network-outbound (remote tcp \"*:{port}\"))\n"));
    }
    if spec.syscalls == SyscallProfile::NetworkClient {
        profile.push_str(concat!(
            "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n",
            "(allow mach-lookup\n",
            "    (global-name \"com.apple.dnssd.service\")\n",
            "    (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")\n",
            "    (global-name \"com.apple.SystemConfiguration.configd\")\n",
            "    (global-name \"com.apple.trustd\")\n",
            "    (global-name \"com.apple.trustd.agent\")\n",
            "    (global-name \"com.apple.SecurityServer\")\n",
            "    (global-name \"com.apple.ocspd\"))\n",
        ));
    }
    profile
}

/// A path as an SBPL string literal body, or `None` for paths with control characters.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn sbpl_escape(path: &Path) -> Option<String> {
    let path = path.to_str()?;
    if path.chars().any(char::is_control) {
        return None;
    }
    Some(path.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_existing_paths_with_their_targets() {
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real.pem");
        std::fs::write(&real, b"").unwrap();
        let link = base.join("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let paths = existing_with_targets([link.clone(), base.join("missing"), real.clone(), link.clone()]);
        assert_eq!(paths, vec![link, real]);
    }

    #[test]
    fn git_worker_spec() {
        let spec = SandboxSpec::git_worker();
        assert_eq!(spec.tcp_connect_ports, vec![443]);
        assert_eq!(spec.syscalls, SyscallProfile::NetworkClient);
        assert!(spec.read_paths.iter().all(|p| p.is_absolute() && p.exists()));
        if Path::new("/etc/hosts").exists() {
            assert!(spec.read_paths.iter().any(|p| p == Path::new("/etc/hosts")));
        }
    }

    #[test]
    fn macos_profiles() {
        let gpg = macos_profile(&SandboxSpec::gpg_worker());
        assert!(gpg.starts_with("(version 1)\n(deny default)\n"));
        assert!(!gpg.contains("network-outbound"));
        assert!(!gpg.contains("file-read*"));

        let dir = tempfile::tempdir().unwrap();
        let spec = SandboxSpec {
            read_paths: vec![
                dir.path().to_path_buf(),
                PathBuf::from("/x/a\"b"),
                PathBuf::from("/x/bad\nline"),
            ],
            tcp_connect_ports: vec![443],
            syscalls: SyscallProfile::NetworkClient,
        };
        let git = macos_profile(&spec);
        assert!(git.contains(&format!("(subpath \"{}\")", dir.path().display())));
        assert!(git.contains("(literal \"/x/a\\\"b\")"));
        assert!(!git.contains("bad"));
        assert!(git.contains("(allow network-outbound (remote tcp \"*:443\"))"));
        assert!(git.contains("com.apple.trustd"));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use crate::testutil::run_in_child;
        use std::io::{Read, Write};
        use std::os::fd::AsFd;

        fn report_has(report: &SandboxReport, layer: Layer) -> bool {
            report.applied.contains(&layer)
        }

        fn seccomp_expected() -> bool {
            matches!(std::env::consts::ARCH, "x86_64" | "aarch64" | "riscv64")
        }

        #[test]
        fn gpg_worker_sandbox() {
            if run_in_child("sandbox::tests::linux::gpg_worker_sandbox") {
                return;
            }
            let secret_file = tempfile::NamedTempFile::new().unwrap();
            let (core, worker) = crate::channel::channel_pair().unwrap();
            let report = apply(&SandboxSpec::gpg_worker()).expect("sandbox applies");
            eprintln!("report: {report:?}");
            assert!(report_has(&report, Layer::NoNewPrivs));
            assert_eq!(report.applied.len() + report.missing.len(), 4);

            // A descriptor handed over the channel works.
            let (r, mut w) = std::io::pipe().unwrap();
            crate::channel::send_with_fds(&core, b"o", &[r.as_fd()]).unwrap();
            drop(r);
            let mut buf = [0u8; 1];
            let (_, mut fds) = crate::channel::recv_with_fds(&worker, &mut buf).unwrap();
            w.write_all(b"turn").unwrap();
            drop(w);
            let mut got = String::new();
            std::io::PipeReader::from(fds.remove(0)).read_to_string(&mut got).unwrap();
            assert_eq!(got, "turn");

            // Threads still work.
            assert_eq!(std::thread::spawn(|| 7).join().unwrap(), 7);

            if report_has(&report, Layer::LandlockFs) || report_has(&report, Layer::Seccomp) {
                assert!(std::fs::read(secret_file.path()).is_err());
                assert!(std::fs::read("/etc/hosts").is_err());
            }
            if report_has(&report, Layer::Seccomp) {
                assert!(std::net::TcpStream::connect("127.0.0.1:443").is_err());
                let socket = rustix::net::socket(
                    rustix::net::AddressFamily::INET,
                    rustix::net::SocketType::STREAM,
                    None,
                );
                assert_eq!(socket.unwrap_err(), rustix::io::Errno::PERM);
                // No new processes.
                assert!(std::process::Command::new("/bin/sh").arg("-c").arg("true").status().is_err());
            } else {
                assert!(!seccomp_expected(), "seccomp missing: {:?}", report.missing);
            }
            std::process::exit(0);
        }

        #[test]
        fn git_worker_sandbox() {
            if run_in_child("sandbox::tests::linux::git_worker_sandbox") {
                return;
            }
            let secret_file = tempfile::NamedTempFile::new().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            assert_ne!(port, 443);
            let spec = SandboxSpec::git_worker();
            let report = apply(&spec).expect("sandbox applies");
            eprintln!("report: {report:?}");
            assert!(report_has(&report, Layer::NoNewPrivs));

            assert_eq!(std::thread::spawn(|| 7).join().unwrap(), 7);
            if Path::new("/etc/hosts").exists() {
                std::fs::read("/etc/hosts").expect("DNS files stay readable");
            }
            // Name resolution through the C library (NSS, /etc/hosts) still works.
            use std::net::ToSocketAddrs;
            let resolved = ("localhost", 443).to_socket_addrs().expect("resolve localhost");
            assert!(resolved.into_iter().any(|a| a.ip().is_loopback()));
            // The CA bundle, if the system has one, is readable.
            for file in spec.read_paths.iter().filter(|p| p.is_file()) {
                std::fs::read(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
            }
            if report_has(&report, Layer::LandlockFs) {
                assert!(std::fs::read(secret_file.path()).is_err());
                assert!(std::fs::write("/tmp/credential-bridge-sandbox-test", b"x").is_err());
            }
            if report_has(&report, Layer::LandlockNet) {
                let err = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
            }
            if report_has(&report, Layer::Seccomp) {
                assert!(std::process::Command::new("/bin/sh").arg("-c").arg("true").status().is_err());
                // UDP sockets for DNS are allowed.
                std::net::UdpSocket::bind("127.0.0.1:0").expect("udp socket");
                // Unix sockets are not: they would reach the daemon, agents or D-Bus.
                let unix = rustix::net::socket(
                    rustix::net::AddressFamily::UNIX,
                    rustix::net::SocketType::STREAM,
                    None,
                );
                assert_eq!(unix.unwrap_err(), rustix::io::Errno::PERM);
            } else {
                assert!(!seccomp_expected(), "seccomp missing: {:?}", report.missing);
            }
            std::process::exit(0);
        }
    }
}
