//! seccomp-bpf allowlists for the sandboxed workers (Linux, x86_64 / aarch64 / riscv64).
//!
//! Two filters are installed: the allowlist (everything else fails with `EPERM`) and a
//! small one that answers `clone3` with `ENOSYS`, so glibc falls back to `clone`, whose
//! flags can be checked (threads only, no new processes). The kernel combines stacked
//! filters by taking the most restrictive answer.
//!
//! The lists are what std threads, tokio, rustls and glibc/musl name resolution need;
//! they are verified by the tests of this crate and by running the workers ("Still to
//! verify" in `docs/architecture.md`).

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};

use super::SyscallProfile;

/// Compiled filters, in the order they are installed.
#[derive(Debug)]
pub(super) struct Programs(Vec<BpfProgram>);

/// Compiles the filters for `profile` on this architecture.
pub(super) fn programs(profile: SyscallProfile) -> Result<Programs, Unsupported> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|_| Unsupported)?;
    let rules = rules(profile).ok_or(Unsupported)?;
    let allowlist =
        SeccompFilter::new(rules, SeccompAction::Errno(libc::EPERM as u32), SeccompAction::Allow, arch)
            .and_then(BpfProgram::try_from)
            .map_err(|_| Unsupported)?;
    // The allowlist goes last: installing a filter calls `prctl(PR_SET_NO_NEW_PRIVS)` and
    // `seccomp`, which the allowlist does not allow.
    let no_clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .and_then(BpfProgram::try_from)
    .map_err(|_| Unsupported)?;
    Ok(Programs(vec![no_clone3, allowlist]))
}

/// Installs `programs`, in order, on every thread of the process. `no_new_privs` must
/// be set.
pub(super) fn install(programs: &Programs) -> Result<(), String> {
    for program in &programs.0 {
        seccompiler::apply_filter_all_threads(program).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// No filter for this architecture.
#[derive(Debug)]
pub(super) struct Unsupported;

fn rules(profile: SyscallProfile) -> Option<BTreeMap<i64, Vec<SeccompRule>>> {
    use libc::*;

    let mut map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut allow = |syscalls: &[i64]| {
        for &nr in syscalls {
            map.insert(nr, Vec::new());
        }
    };

    // Memory, threads, signals, time, process identity.
    allow(&[
        SYS_brk,
        SYS_mmap,
        SYS_munmap,
        SYS_mremap,
        SYS_mprotect,
        SYS_madvise,
        SYS_futex,
        SYS_set_robust_list,
        SYS_get_robust_list,
        SYS_rseq,
        SYS_set_tid_address,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        SYS_rt_sigaction,
        SYS_rt_sigprocmask,
        SYS_rt_sigreturn,
        SYS_sigaltstack,
        SYS_restart_syscall,
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_clock_nanosleep,
        SYS_nanosleep,
        SYS_gettimeofday,
        SYS_getrandom,
        SYS_getpid,
        SYS_gettid,
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_uname,
        SYS_exit,
        SYS_exit_group,
    ]);
    // Descriptors the process already holds: the channel, received descriptors, the
    // event loop.
    allow(&[
        SYS_read,
        SYS_readv,
        SYS_write,
        SYS_writev,
        SYS_close,
        SYS_fstat,
        SYS_newfstatat,
        SYS_statx,
        SYS_lseek,
        SYS_fcntl,
        SYS_ppoll,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_pwait,
        SYS_epoll_pwait2,
        SYS_eventfd2,
        SYS_pipe2,
        SYS_recvmsg,
        SYS_sendmsg,
        SYS_recvfrom,
        SYS_sendto,
        SYS_shutdown,
        SYS_getsockopt,
    ]);
    #[cfg(target_arch = "x86_64")]
    allow(&[SYS_poll, SYS_epoll_wait]);

    if profile == SyscallProfile::NetworkClient {
        // Files (limited by Landlock), sockets (TCP limited by Landlock), name
        // resolution (netlink for `AI_ADDRCONFIG`). No unix sockets: Landlock does not
        // restrict connecting to pathname sockets, so the worker could otherwise reach
        // the daemon's own sockets, other agents or the session bus. glibc falls back
        // from nscd and nss-resolve to `/etc/resolv.conf` when `socket(AF_UNIX)` fails.
        allow(&[
            SYS_openat,
            SYS_pread64,
            SYS_getdents64,
            SYS_readlinkat,
            SYS_faccessat,
            SYS_faccessat2,
            SYS_connect,
            SYS_bind,
            SYS_getsockname,
            SYS_getpeername,
            SYS_setsockopt,
            SYS_sendmmsg,
            SYS_recvmmsg,
        ]);
        #[cfg(target_arch = "x86_64")]
        allow(&[SYS_open, SYS_stat, SYS_lstat, SYS_access, SYS_readlink]);
        map.insert(
            SYS_socket,
            [AF_INET, AF_INET6, AF_NETLINK]
                .into_iter()
                .map(|domain| rule(&[(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain as u64)]))
                .collect::<Option<_>>()?,
        );
    }

    // Threads only: `clone` must carry CLONE_THREAD (no new processes).
    map.insert(
        SYS_clone,
        vec![rule(&[(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(CLONE_THREAD as u64),
            CLONE_THREAD as u64,
        )])?],
    );
    map.insert(SYS_clone3, Vec::new());
    // Non-blocking mode and close-on-exec on sockets.
    map.insert(
        SYS_ioctl,
        ioctl_requests()
            .into_iter()
            .map(|request| rule(&[(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, request)]))
            .collect::<Option<_>>()?,
    );
    // Thread names.
    map.insert(
        SYS_prctl,
        [PR_SET_NAME, PR_GET_NAME]
            .into_iter()
            .map(|option| rule(&[(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, option as u64)]))
            .collect::<Option<_>>()?,
    );
    // `abort` and panics signal only this process.
    let own_pid = u64::from(std::process::id());
    map.insert(SYS_tgkill, vec![rule(&[(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, own_pid)])?]);

    Some(map)
}

/// `FIONBIO` and `FIOCLEX`; their C type differs between glibc and musl.
#[allow(clippy::unnecessary_cast)]
fn ioctl_requests() -> [u64; 2] {
    [libc::FIONBIO as u64, libc::FIOCLEX as u64]
}

fn rule(conditions: &[(u8, SeccompCmpArgLen, SeccompCmpOp, u64)]) -> Option<SeccompRule> {
    let conditions = conditions
        .iter()
        .map(|(arg, len, op, value)| SeccompCondition::new(*arg, len.clone(), op.clone(), *value).ok())
        .collect::<Option<Vec<_>>>()?;
    SeccompRule::new(conditions).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_both_profiles() {
        for profile in [SyscallProfile::NetworkClient, SyscallProfile::DescriptorRelay] {
            let programs = programs(profile).unwrap();
            assert_eq!(programs.0.len(), 2);
            assert!(programs.0.iter().all(|p| !p.is_empty()));
        }
    }

    #[test]
    fn relay_profile_has_no_files_or_sockets() {
        let relay = rules(SyscallProfile::DescriptorRelay).unwrap();
        for nr in [libc::SYS_openat, libc::SYS_socket, libc::SYS_connect, libc::SYS_execve, libc::SYS_bind] {
            assert!(!relay.contains_key(&nr), "syscall {nr} must not be allowed");
        }
        let client = rules(SyscallProfile::NetworkClient).unwrap();
        for nr in [libc::SYS_execve, libc::SYS_execveat, libc::SYS_ptrace, libc::SYS_kill, libc::SYS_listen] {
            assert!(!client.contains_key(&nr), "syscall {nr} must not be allowed");
        }
        assert!(client.contains_key(&libc::SYS_openat));
    }
}
