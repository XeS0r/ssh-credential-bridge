//! Test helpers: run one test in a fresh process of the test binary, for tests that
//! change the whole process irreversibly (hardening, sandboxes, stdin).

use std::process::{Command, Stdio};

/// Environment variable that marks the child process and names its test.
const CHILD_ENV: &str = "CREDENTIAL_BRIDGE_PLATFORM_TEST_CHILD";

/// In the parent: runs the test `name` (its full path, e.g. `sandbox::tests::gpg`) in a
/// child process of the test binary, asserts that it succeeded and returns `true`.
/// In that child: returns `false`, and the caller runs the actual test body.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn run_in_child(name: &str) -> bool {
    run_in_child_with(name, |command| {
        command.stdin(Stdio::null());
    })
}

/// [`run_in_child`] with a hook to adjust the child's command (stdin, environment).
pub(crate) fn run_in_child_with(name: &str, configure: impl FnOnce(&mut Command)) -> bool {
    if std::env::var_os(CHILD_ENV).is_some_and(|v| v == name) {
        return false;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = Command::new(exe);
    command.args([name, "--exact", "--nocapture", "--test-threads=1"]).env(CHILD_ENV, name);
    configure(&mut command);
    let output = command.output().expect("spawn test child");
    assert!(
        output.status.success(),
        "child test {name} failed with {}\n--- stdout\n{}\n--- stderr\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    // An unknown name runs zero tests and also succeeds.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("running 1 test"), "child test {name} did not run:\n{stdout}");
    true
}
