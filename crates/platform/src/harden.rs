//! Memory protection for every credential-bridge process (security rule 7).

/// What [`harden_process`] achieved. Failures are not fatal; the caller logs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningReport {
    /// Other processes of the user cannot attach or read memory
    /// (Linux `PR_SET_DUMPABLE=0`, macOS `PT_DENY_ATTACH`).
    pub non_dumpable: bool,
    /// Core dumps are disabled (`RLIMIT_CORE` = 0).
    pub no_core_dumps: bool,
    /// One message per step that failed.
    pub failures: Vec<String>,
}

/// Makes the process non-dumpable and disables core dumps. Call first thing in `main`,
/// before any secret is in memory. Idempotent.
pub fn harden_process() -> HardeningReport {
    let mut report = HardeningReport::default();

    match deny_inspection() {
        Ok(()) => report.non_dumpable = true,
        Err(e) => report.failures.push(e),
    }

    let zero = rustix::process::Rlimit { current: Some(0), maximum: Some(0) };
    match rustix::process::setrlimit(rustix::process::Resource::Core, zero) {
        Ok(()) => report.no_core_dumps = true,
        Err(e) => report.failures.push(format!("setting RLIMIT_CORE to 0 failed: {e}")),
    }

    report
}

#[cfg(target_os = "linux")]
fn deny_inspection() -> Result<(), String> {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("prctl(PR_SET_DUMPABLE, 0) failed: {e}"))
}

#[cfg(target_os = "macos")]
fn deny_inspection() -> Result<(), String> {
    crate::macos::deny_attach().map_err(|e| format!("ptrace(PT_DENY_ATTACH) failed: {e}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn deny_inspection() -> Result<(), String> {
    Err("no protection against debuggers on this platform".to_owned())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::testutil::run_in_child;

    #[test]
    fn hardens_a_child_process() {
        if run_in_child("harden::tests::hardens_a_child_process") {
            return;
        }
        let first = harden_process();
        assert_eq!(first, HardeningReport { non_dumpable: true, no_core_dumps: true, failures: Vec::new() });
        // Idempotent.
        assert_eq!(harden_process(), first);
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
    }
}
