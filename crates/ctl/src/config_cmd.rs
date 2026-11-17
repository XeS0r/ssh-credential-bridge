//! `config …` commands.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

use anyhow::{Context, bail};
use credential_bridge_core::config::{Config, EXAMPLE_CONFIG};

use crate::{ConfigCommand, Ctx, service};

pub fn run(ctx: &Ctx, cmd: ConfigCommand) -> anyhow::Result<()> {
    let path = &ctx.config_path;
    match cmd {
        ConfigCommand::Path => println!("{}", path.display()),
        ConfigCommand::Show => match fs::read_to_string(path) {
            Ok(text) => print!("{text}"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                println!("# {} does not exist; defaults apply (no remotes)", path.display());
            }
            Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
        },
        ConfigCommand::Init => {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }
            let mut file =
                fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(
                    |err| match err.kind() {
                        io::ErrorKind::AlreadyExists => anyhow::anyhow!("{} already exists", path.display()),
                        _ => anyhow::Error::new(err).context(format!("cannot create {}", path.display())),
                    },
                )?;
            file.write_all(EXAMPLE_CONFIG.as_bytes())?;
            println!("wrote {}", path.display());
        }
        ConfigCommand::Edit => {
            if !path.exists() {
                run(ctx, ConfigCommand::Init)?;
            }
            let editor = pick_editor(|name| env::var(name).ok());
            // $EDITOR may carry arguments ("code --wait"), so let the shell split it.
            crate::util::run(
                Command::new("/bin/sh").arg("-c").arg(format!("{editor} \"$1\"")).arg("editor").arg(path),
            )?;
            match Config::load(path) {
                Ok(_) => {
                    println!("configuration is valid");
                    service::reload_if_active(ctx);
                }
                Err(err) => bail!("{err}\nfix it with `credential-bridge-ctl config edit`"),
            }
        }
        ConfigCommand::Validate => {
            let config = Config::load(path)?;
            println!("{} is valid ({} remotes)", path.display(), config.remotes.len());
        }
    }
    Ok(())
}

/// `$VISUAL`, else `$EDITOR`, else `vi`; empty values count as unset, as in git.
fn pick_editor(get: impl Fn(&str) -> Option<String>) -> String {
    ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(|name| get(name).filter(|value| !value.trim().is_empty()))
        .next()
        .unwrap_or_else(|| "vi".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_visual_falls_back_to_editor() {
        let env = |visual: &str, editor: Option<&str>| {
            let visual = visual.to_owned();
            let editor = editor.map(str::to_owned);
            move |name: &str| match name {
                "VISUAL" => Some(visual.clone()),
                "EDITOR" => editor.clone(),
                _ => None,
            }
        };
        assert_eq!(pick_editor(env("", Some("nano"))), "nano");
        assert_eq!(pick_editor(env("code --wait", Some("nano"))), "code --wait");
        assert_eq!(pick_editor(env(" ", None)), "vi");
    }
}
