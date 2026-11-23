//! `profile add|list|show|set|remove` and `profile rule add|list|remove`.

use anyhow::{Context as _, bail};
use credential_bridge_config::edit::{NewRule, ProfileKey, ProfileSetting};
use credential_bridge_config::{Config, KeySelection, Profile, SourceKind, UNREGISTERED_PROFILE};
use credential_bridge_proto::ipc::git::TokenScope;

use super::change::{apply, edit_error};
use super::check::unregistered_line;
use super::github_app::parse_permission_list;
use super::server::profile_text;
use super::{Context, load_config};
use crate::cli::{
    NameArg, NameWriteArgs, PerArg, ProfileAddArgs, ProfileCommand, ProfileSetArgs, RuleAddArgs, RuleCommand,
    RuleRemoveArgs,
};
use crate::report::Report;

/// Runs a `profile` subcommand.
pub fn profile(ctx: &Context, command: &ProfileCommand, report: &mut Report) -> anyhow::Result<()> {
    match command {
        ProfileCommand::Add(args) => profile_add(ctx, args, report),
        ProfileCommand::List => {
            let config = load_config(ctx)?;
            report.show(&profile_table(&config));
            Ok(())
        }
        ProfileCommand::Show(NameArg { name }) => {
            let config = load_config(ctx)?;
            report.show(&show_text(&config, name)?);
            Ok(())
        }
        ProfileCommand::Set(args) => profile_set(ctx, args, report),
        ProfileCommand::Remove(NameWriteArgs { name, write }) => {
            let summary = if name == UNREGISTERED_PROFILE {
                "[profile.unregistered] removed: the built-in defaults apply".to_owned()
            } else {
                format!("[profile.{name}] removed")
            };
            let applied = apply(ctx, write.dry_run, report, &summary, |doc| doc.remove_profile(name))?;
            if name == UNREGISTERED_PROFILE
                && let Some(applied) = applied
            {
                report.push(unregistered_line(&applied.config));
            }
            Ok(())
        }
        ProfileCommand::Rule(command) => rule(ctx, command, report),
    }
}

/// Parses `KEY=VALUE` settings; every mistake is reported before anything changes.
fn settings(values: &[String]) -> anyhow::Result<Vec<ProfileSetting>> {
    values.iter().map(|value| ProfileSetting::parse(value).map_err(edit_error)).collect()
}

/// `profile add NAME [KEY=VALUE…]`.
fn profile_add(ctx: &Context, args: &ProfileAddArgs, report: &mut Report) -> anyhow::Result<()> {
    let settings = settings(&args.settings)?;
    let summary = format!("[profile.{}] added", args.name);
    apply(ctx, args.write.dry_run, report, &summary, |doc| {
        doc.add_profile(&args.name)?;
        settings.iter().try_for_each(|setting| doc.set_profile(&args.name, setting))
    })?;
    Ok(())
}

/// `profile set NAME [KEY=VALUE…] [--unset KEY…]`. For `unregistered`, the effective
/// profile is reported with the warnings of `check`.
fn profile_set(ctx: &Context, args: &ProfileSetArgs, report: &mut Report) -> anyhow::Result<()> {
    let settings = settings(&args.settings)?;
    let unset: Vec<ProfileKey> = args
        .unset
        .iter()
        .map(|key| key.parse::<ProfileKey>().map_err(edit_error))
        .collect::<anyhow::Result<_>>()?;
    if settings.is_empty() && unset.is_empty() {
        bail!("nothing to set: give KEY=VALUE or --unset KEY (see credential-bridge-ctl profile set --help)");
    }
    if let Some(key) = unset.iter().find(|key| settings.iter().any(|setting| setting.key() == **key)) {
        bail!("{} is both set and unset", key.name());
    }
    let mut changed: Vec<String> = args.settings.clone();
    changed.extend(unset.iter().map(|key| format!("{} unset", key.name())));
    let summary = format!("[profile.{}] {}", args.name, changed.join(", "));
    let applied = apply(ctx, args.write.dry_run, report, &summary, |doc| {
        for setting in &settings {
            doc.set_profile(&args.name, setting)?;
        }
        for key in &unset {
            doc.unset_profile(&args.name, *key)?;
        }
        Ok(())
    })?;
    if args.name == UNREGISTERED_PROFILE
        && let Some(applied) = applied
    {
        report.push(unregistered_line(&applied.config));
    }
    Ok(())
}

/// Runs a `profile rule` subcommand.
fn rule(ctx: &Context, command: &RuleCommand, report: &mut Report) -> anyhow::Result<()> {
    match command {
        RuleCommand::Add(args) => rule_add(ctx, args, report),
        RuleCommand::List(NameArg { name }) => {
            let config = load_config(ctx)?;
            let profile = find(&config, name)?;
            report.show(&rule_table(&config, profile));
            Ok(())
        }
        RuleCommand::Remove(RuleRemoveArgs { profile, url, write }) => {
            let summary = format!("[[profile.{profile}.git]] {url} removed");
            apply(ctx, write.dry_run, report, &summary, |doc| doc.remove_rule(profile, url))?;
            Ok(())
        }
    }
}

/// `profile rule add PROFILE URL --source NAME …`.
fn rule_add(ctx: &Context, args: &RuleAddArgs, report: &mut Report) -> anyhow::Result<()> {
    let rule = NewRule {
        url: args.url.clone(),
        source: args.source.clone(),
        permissions: parse_permission_list("--permission", &args.permissions)?,
        per: args.per.map(|per| match per {
            PerArg::Repo => TokenScope::Repo,
            PerArg::Owner => TokenScope::Owner,
        }),
    };
    let summary = format!("[[profile.{}.git]] {} -> {} added", args.profile, args.url, args.source);
    apply(ctx, args.write.dry_run, report, &summary, |doc| {
        doc.add_rule(&args.profile, &rule, args.before.as_deref())
    })?;
    Ok(())
}

/// Profile `name`, including `unregistered`.
fn find<'a>(config: &'a Config, name: &str) -> anyhow::Result<&'a Profile> {
    if name == UNREGISTERED_PROFILE {
        return Ok(&config.unregistered);
    }
    config.profiles.get(name).with_context(|| {
        let known: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
        format!(
            "no [profile.{name}] (known: {})",
            if known.is_empty() { "none".to_owned() } else { known.join(", ") }
        )
    })
}

/// Short text for `ssh`: `all`, `fido, yubikey`, `none`.
fn keys_summary(profile: &Profile) -> String {
    match &profile.ssh {
        None => "none".to_owned(),
        Some(ssh) => match &ssh.keys {
            KeySelection::All => format!("all, confirm {}", ssh.confirm.describe()),
            KeySelection::Upstreams(names) if names.is_empty() => "none".to_owned(),
            KeySelection::Upstreams(names) => {
                format!("{}, confirm {}", names.join(","), ssh.confirm.describe())
            }
        },
    }
}

/// The table `profile list` prints, with `unregistered` last.
fn profile_table(config: &Config) -> String {
    let mut rows: Vec<(String, String, String, String)> = config
        .profiles
        .values()
        .map(|profile| {
            let servers: Vec<&str> = config
                .servers
                .values()
                .filter(|server| server.profile == profile.name)
                .map(|server| server.name.as_str())
                .collect();
            (
                profile.name.clone(),
                keys_summary(profile),
                profile.git.len().to_string(),
                if servers.is_empty() { "-".to_owned() } else { servers.join(", ") },
            )
        })
        .collect();
    rows.push((
        format!("{UNREGISTERED_PROFILE} (built in)"),
        keys_summary(&config.unregistered),
        "0".to_owned(),
        "hosts without [server.*]".to_owned(),
    ));
    let width = rows.iter().map(|row| row.0.len()).max().unwrap_or(0).max(7);
    let keys_width = rows.iter().map(|row| row.1.len()).max().unwrap_or(0).max(8);
    let mut out = format!("{:<width$}  {:<keys_width$}  RULES  SERVERS\n", "PROFILE", "SSH KEYS");
    for (name, keys, rules, servers) in rows {
        out.push_str(&format!("{name:<width$}  {keys:<keys_width$}  {rules:<5}  {servers}\n"));
    }
    out
}

/// What `profile show` prints.
fn show_text(config: &Config, name: &str) -> anyhow::Result<String> {
    let profile = find(config, name)?;
    let mut out = format!("profile     {name}\n");
    if name == UNREGISTERED_PROFILE {
        out.push_str("            built in, for hosts without a [server.*] entry; never tokens or gpg\n");
    } else {
        let servers: Vec<&str> =
            config.servers.values().filter(|s| s.profile == name).map(|s| s.name.as_str()).collect();
        out.push_str(&format!(
            "servers     {}\n",
            if servers.is_empty() { "none".to_owned() } else { servers.join(", ") }
        ));
    }
    out.push_str(&profile_text(config, profile));
    Ok(out)
}

/// The table `profile rule list` prints.
fn rule_table(config: &Config, profile: &Profile) -> String {
    if profile.git.is_empty() {
        return format!(
            "profile {} has no git rules; add one with:\n  credential-bridge-ctl profile rule add {} URL --source NAME\n",
            profile.name, profile.name
        );
    }
    let width = profile.git.iter().map(|rule| rule.url.as_str().len()).max().unwrap_or(0).max(3);
    let mut out = format!("#  {:<width$}  SOURCE\n", "URL");
    for (index, rule) in profile.git.iter().enumerate() {
        let mut line = format!("{index:<2} {:<width$}  {}", rule.url.as_str(), rule.source);
        let is_app = config
            .sources
            .get(&rule.source)
            .is_some_and(|source| matches!(source.kind, SourceKind::GithubApp { .. }));
        if !rule.permissions.is_empty() {
            let permissions: Vec<String> =
                rule.permissions.iter().map(|(name, access)| format!("{name}={access}")).collect();
            line.push_str(&format!("  {}", permissions.join(",")));
        }
        if is_app {
            line.push_str(&format!("  per {}", rule.per));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::WriteArgs;
    use crate::commands::test_support::{context, test_key, write_config};

    const TEXT: &str = "version = 2\n\n[[agent.upstream]]\nname = \"fido\"\nsocket = \"/fido.sock\"\n\n\
                        [source.github]\ntype = \"github\"\nauth = \"gh\"\n\n\
                        # for build machines\n[profile.build]\nssh = { keys = \"all\" }   # everything\n";

    fn run(ctx: &Context, command: ProfileCommand) -> anyhow::Result<Report> {
        let mut report = Report::default();
        profile(ctx, &command, &mut report).map(|()| report)
    }

    fn set(name: &str, settings: &[&str], unset: &[&str]) -> ProfileCommand {
        ProfileCommand::Set(ProfileSetArgs {
            name: name.into(),
            settings: settings.iter().map(|s| (*s).to_owned()).collect(),
            unset: unset.iter().map(|s| (*s).to_owned()).collect(),
            write: WriteArgs::default(),
        })
    }

    fn add_rule(profile: &str, url: &str, source: &str) -> ProfileCommand {
        ProfileCommand::Rule(RuleCommand::Add(RuleAddArgs {
            profile: profile.into(),
            url: url.into(),
            source: source.into(),
            permissions: Vec::new(),
            per: None,
            before: None,
            write: WriteArgs::default(),
        }))
    }

    fn text(ctx: &Context) -> String {
        std::fs::read_to_string(&ctx.config_path).unwrap()
    }

    #[test]
    fn add_set_unset_keep_comments() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        run(
            &ctx,
            ProfileCommand::Add(ProfileAddArgs {
                name: "dev".into(),
                settings: vec!["ssh.keys=fido".into(), "signing=ssh".into()],
                write: WriteArgs::default(),
            }),
        )
        .unwrap();
        run(&ctx, set("build", &["ssh.confirm=8h", "hops.ssh=false"], &[])).unwrap();
        let text = text(&ctx);
        assert!(text.contains("# for build machines\n[profile.build]\nssh = { keys = \"all\", confirm = \"8h\" }   # everything\nhops = { ssh = false }\n"), "{text}");
        assert!(text.ends_with("[profile.dev]\nssh = { keys = [\"fido\"] }\nsigning = \"ssh\"\n"), "{text}");
        run(&ctx, set("build", &[], &["ssh.confirm", "hops.ssh"])).unwrap();
        run(&ctx, ProfileCommand::Remove(NameWriteArgs { name: "dev".into(), write: WriteArgs::default() }))
            .unwrap();
        assert_eq!(self::text(&ctx), TEXT);
    }

    #[test]
    fn bad_settings_change_nothing() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        for (command, hint) in [
            (set("build", &["ssh.confirm=8h", "ssh.keys=a b"], &[]), "not an upstream name"),
            (set("build", &["colour=blue"], &[]), "unknown profile key"),
            (set("build", &[], &["colour"]), "unknown profile key"),
            (set("build", &["signing=ssh"], &["signing"]), "both set and unset"),
            (set("build", &[], &[]), "nothing to set"),
            (set("nope", &["signing=ssh"], &[]), "no profile.nope"),
            (set("build", &["ssh.keys=yubikey"], &[]), "\"yubikey\" is not an [[agent.upstream]] name"),
            (set("build", &["gpg=sign"], &[]), "no [gpg] table"),
            (set("unregistered", &["gpg=sign"], &[]), "allows only ssh.keys"),
        ] {
            let message = format!("{:#}", run(&ctx, command).unwrap_err());
            assert!(message.contains(hint), "{hint}: {message}");
        }
        assert_eq!(text(&ctx), TEXT);
    }

    #[test]
    fn loosening_unregistered_warns_like_check() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let report = run(&ctx, set("unregistered", &["ssh.keys=all", "ssh.confirm=never"], &[])).unwrap();
        let warning = report.lines.last().unwrap().to_string();
        assert!(warning.starts_with("⚠ unregistered"), "{warning}");
        assert!(
            warning.contains("keys = \"all\" shows every key") && warning.contains("confirm = \"never\""),
            "{warning}"
        );
        assert!(
            text(&ctx).ends_with("[profile.unregistered]\nssh = { keys = \"all\", confirm = \"never\" }\n")
        );
        let report = run(
            &ctx,
            ProfileCommand::Remove(NameWriteArgs {
                name: "unregistered".into(),
                write: WriteArgs::default(),
            }),
        )
        .unwrap();
        assert!(
            report.lines.last().unwrap().to_string().ends_with(" no keys, no tokens, no gpg"),
            "{}",
            report.text
        );
        assert_eq!(text(&ctx), TEXT);
    }

    #[test]
    fn remove_refuses_profiles_in_use() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            &format!("{TEXT}\n[server.box]\nhost_keys = [\"{}\"]\nprofile = \"build\"\n", test_key(1)),
        );
        let message = format!(
            "{:#}",
            run(
                &ctx,
                ProfileCommand::Remove(NameWriteArgs { name: "build".into(), write: WriteArgs::default() })
            )
            .unwrap_err()
        );
        assert!(message.contains("profile \"build\" is still used by server.box"), "{message}");
        assert!(message.contains("credential-bridge-ctl server set box --profile OTHER"), "{message}");
        let list = run(&ctx, ProfileCommand::List).unwrap().text;
        assert!(list.contains("build                    all, confirm never  0      box"), "{list}");
        assert!(list.contains("unregistered (built in)  none"), "{list}");
    }

    /// The hint about a server's git config comes only when a rule change alters its
    /// git hosts, and never on a dry run.
    #[test]
    fn rule_changes_hint_at_the_git_config_only_when_it_changes() {
        let (_dir, ctx) = context();
        write_config(
            &ctx,
            &format!("{TEXT}\n[server.box]\nhost_keys = [\"{}\"]\nprofile = \"build\"\n", test_key(1)),
        );
        let hinted = |report: &Report| report.lines.iter().any(|line| line.label == "git config");
        let rule = |url: &str, dry_run: bool| {
            let mut command = add_rule("build", url, "github");
            if let ProfileCommand::Rule(RuleCommand::Add(args)) = &mut command {
                args.write.dry_run = dry_run;
            }
            command
        };
        let remove = |url: &str| {
            ProfileCommand::Rule(RuleCommand::Remove(RuleRemoveArgs {
                profile: "build".into(),
                url: url.into(),
                write: WriteArgs::default(),
            }))
        };
        assert!(!hinted(&run(&ctx, rule("https://github.com/*", true)).unwrap()));
        let report = run(&ctx, rule("https://github.com/*", false)).unwrap();
        assert!(hinted(&report), "{}", report.text);
        assert!(
            report.text.contains("credential-bridge-ctl server add box --profile build"),
            "{}",
            report.text
        );
        assert!(!hinted(&run(&ctx, rule("https://github.com/*/*", false)).unwrap()));
        assert!(!hinted(&run(&ctx, remove("https://github.com/*/*")).unwrap()));
        assert!(hinted(&run(&ctx, remove("https://github.com/*")).unwrap()));
        // So does signing.
        assert!(hinted(&run(&ctx, set("build", &["signing=ssh"], &[])).unwrap()));
    }

    #[test]
    fn rules() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        run(&ctx, add_rule("build", "https://github.com/*", "github")).unwrap();
        let mut first = add_rule("build", "https://github.com/my-org/*", "github");
        if let ProfileCommand::Rule(RuleCommand::Add(args)) = &mut first {
            args.before = Some("https://github.com/*".into());
        }
        run(&ctx, first).unwrap();
        let list = run(&ctx, ProfileCommand::Rule(RuleCommand::List(NameArg { name: "build".into() })))
            .unwrap()
            .text;
        assert_eq!(
            list,
            "#  URL                          SOURCE\n0  https://github.com/my-org/*  github\n1  https://github.com/*         github\n"
        );
        for (command, hint) in [
            (add_rule("build", "https://gitlab.com/*", "github"), "does not match host github.com"),
            (add_rule("build", "https://github.com/*", "github"), "already exists"),
            (add_rule("build", "github.com/*", "github"), "url:"),
            (add_rule("build", "https://github.com/x/*", "nope"), "\"nope\" is not a [source.*] name"),
            (
                add_rule("unregistered", "https://github.com/x/*", "github"),
                "not allowed in profile.unregistered",
            ),
        ] {
            let message = format!("{:#}", run(&ctx, command).unwrap_err());
            assert!(message.contains(hint), "{hint}: {message}");
        }
        for url in ["https://github.com/*", "https://github.com/my-org/*"] {
            run(
                &ctx,
                ProfileCommand::Rule(RuleCommand::Remove(RuleRemoveArgs {
                    profile: "build".into(),
                    url: url.into(),
                    write: WriteArgs::default(),
                })),
            )
            .unwrap();
        }
        assert_eq!(text(&ctx), TEXT);
    }
}
