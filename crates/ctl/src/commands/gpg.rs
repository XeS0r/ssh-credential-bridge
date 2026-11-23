//! `gpg setup`: prints what to add on a server. ctl never edits gpg files.

use anyhow::Context as _;
use credential_bridge_config::Config;

use super::{Context, load_config, printable};
use crate::cli::GpgSetupArgs;
use crate::remote::{REMOTE_BINARY, RemoteShell, SshShell};

/// `gpg setup`: prints the `gpg.conf` line (`agent-program <path>`), how to export
/// and import the public keys, and what `check` will verify.
pub fn gpg_setup(ctx: &Context, args: &GpgSetupArgs) -> anyhow::Result<()> {
    print!("{}", gpg_setup_with(ctx, args, &SshShell)?);
    Ok(())
}

/// The `gpg.conf` line for a server whose home directory is `remote_home`.
///
/// gpg starts the agent program as `credential-bridge-remote --homedir …
/// --use-standard-socket --daemon`, which the remote binary recognises as the gpg shim.
/// gpg does not expand `~` here, hence the absolute path.
pub fn gpg_conf_line(remote_home: &str) -> String {
    format!("agent-program {}/{REMOTE_BINARY}", remote_home.trim_end_matches('/'))
}

/// The text [`gpg_setup`] prints; asks the server for its home directory.
pub fn gpg_setup_with(ctx: &Context, args: &GpgSetupArgs, shell: &dyn RemoteShell) -> anyhow::Result<String> {
    let config = load_config(ctx)?;
    let name = args.server.as_str();
    let server = config.servers.get(name).with_context(|| format!("no [server.{name}]"))?;
    let home = shell
        .run(name, &["sh", "-c", "printf %s \"$HOME\""])
        .ok()
        .filter(|output| output.success() && output.stdout.starts_with('/') && !output.stdout.contains('\n'))
        .map(|output| printable(&output.stdout));
    let mut out = String::new();
    if !allows_gpg(&config, &server.profile) {
        out.push_str(&format!(
            "Note: profile {} allows no gpg yet; add gpg = [\"sign\"] (or [\"sign\", \"decrypt\"]) to \
             [profile.{}] and a [gpg] table.\n\n",
            server.profile, server.profile
        ));
    }
    let line = match &home {
        Some(home) => gpg_conf_line(home),
        None => {
            out.push_str(&format!(
                "Could not ask {name} for its home directory; replace HOME_ON_SERVER below.\n\n"
            ));
            gpg_conf_line("HOME_ON_SERVER")
        }
    };
    out.push_str(&format!(
        "1. On {name}, add this line to ~/.gnupg/gpg.conf (and make sure it has no \"no-autostart\"):\n\n\
         \x20  {line}\n\n\
         2. Stop a gpg-agent that may already run there, so gpg starts the shim next time:\n\n\
         \x20  ssh {name} gpgconf --kill gpg-agent\n\n\
         3. Copy your public keys there; the secret keys stay on this machine:\n\n\
         \x20  gpg --export --armor KEYID | ssh {name} gpg --import\n\n\
         \x20  (find KEYID with: gpg --list-secret-keys --keyid-format long)\n\n\
         4. Verify with: credential-bridge-ctl check\n"
    ));
    Ok(out)
}

fn allows_gpg(config: &Config, profile: &str) -> bool {
    config.profiles.get(profile).is_some_and(|profile| profile.gpg.sign || profile.gpg.decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{FakeShell, context, test_key, write_config};

    #[test]
    fn prints_the_gpg_conf_line() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            &format!(
                "version = 2\n[gpg]\n[profile.build]\ngpg = [\"sign\"]\n\
                 [server.buildserver]\nhost_keys = [\"{}\"]\nprofile = \"build\"\n",
                test_key(1)
            ),
        );
        let shell = FakeShell::default().answer("sh -c", 0, "/home/me");
        let args = GpgSetupArgs { server: "buildserver".into() };
        let text = gpg_setup_with(&ctx, &args, &shell).unwrap();
        assert!(text.contains("   agent-program /home/me/.local/bin/credential-bridge-remote\n"), "{text}");
        assert!(text.contains("gpg --export --armor KEYID | ssh buildserver gpg --import"));
        assert!(!text.contains("Note:"));

        let text = gpg_setup_with(&ctx, &args, &FakeShell::default()).unwrap();
        assert!(text.contains("agent-program HOME_ON_SERVER/.local/bin/credential-bridge-remote\n"));

        let args = GpgSetupArgs { server: "other".into() };
        assert!(gpg_setup_with(&ctx, &args, &shell).is_err());
    }

    #[test]
    fn notes_profiles_without_gpg() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            &format!(
                "version = 2\n[profile.dev]\n[server.devbox]\nhost_keys = [\"{}\"]\nprofile = \"dev\"\n",
                test_key(2)
            ),
        );
        let shell = FakeShell::default().answer("sh -c", 0, "/home/me");
        let text = gpg_setup_with(&ctx, &GpgSetupArgs { server: "devbox".into() }, &shell).unwrap();
        assert!(text.starts_with("Note: profile dev allows no gpg yet"));
    }
}
