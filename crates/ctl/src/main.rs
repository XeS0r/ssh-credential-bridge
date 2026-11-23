//! `credential-bridge-ctl`: see the library crate `credential_bridge_ctl`.

use std::process::ExitCode;

fn main() -> ExitCode {
    credential_bridge_ctl::cli::main()
}
