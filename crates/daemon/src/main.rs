//! `credential-bridged`: see the library crate `credential_bridged`.

use std::process::ExitCode;

fn main() -> ExitCode {
    credential_bridged::cli::main()
}
