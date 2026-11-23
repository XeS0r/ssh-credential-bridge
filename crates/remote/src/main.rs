//! `credential-bridge-remote`: see the library crate `credential_bridge_remote`.

use std::process::ExitCode;

fn main() -> ExitCode {
    credential_bridge_remote::cli::main()
}
