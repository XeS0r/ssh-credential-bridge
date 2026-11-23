//! `source add|list|show|test|remove`: where tokens come from. `source add github --auth
//! app --create` runs [`github_app_create`].

use anyhow::{Context as _, bail};
use credential_bridge_config::edit::NewSource;
use credential_bridge_config::{Config, Source, SourceKind};

use credential_bridge_proto::ipc::WorkerErrorKind;
use credential_bridge_proto::ipc::control::{Request, Response, SourceCheck};

use super::change::{RELOAD_HINT, apply, secret_ref};
use super::github_app::{github_app_create, parse_permission_list};
use super::{Context, SLOW_CONTROL_TIMEOUT, connect, daemon_config, load_config, printable};
use crate::cli::{
    GithubAuth, GithubSourceArgs, NameArg, NameWriteArgs, SourceAddCommand, SourceCommand, WriteArgs,
};
use crate::control::ControlError;
use crate::report::{Line, Report, Status};

/// Runs a `source` subcommand.
pub fn source(ctx: &Context, command: &SourceCommand, report: &mut Report) -> anyhow::Result<()> {
    match command {
        SourceCommand::Add(SourceAddCommand::Github(args)) if args.create => {
            if args.auth != GithubAuth::App {
                bail!("--create is only used with --auth app");
            }
            github_app_create(ctx, args, report)
        }
        SourceCommand::Add(add) => {
            let (name, new, cache, write) = new_source(add)?;
            let summary = format!("[source.{name}] added");
            let applied = apply(ctx, write.dry_run, report, &summary, |doc| {
                doc.add_source(name, &new)?;
                if !cache {
                    doc.set_source_cache(name, false)?;
                }
                Ok(())
            })?;
            if let Some(applied) = applied.filter(|_| !write.dry_run)
                && let Some(source) = applied.config.sources.get(name)
                && resolves_something(source)
            {
                test_after_add(ctx, &applied.config, name, report);
            }
            Ok(())
        }
        SourceCommand::Test(NameArg { name }) => source_test(ctx, name, report),
        SourceCommand::List => {
            let config = load_config(ctx)?;
            report.show(&source_table(&config));
            Ok(())
        }
        SourceCommand::Show(NameArg { name }) => {
            let config = load_config(ctx)?;
            let source = config.sources.get(name).with_context(|| format!("no [source.{name}]"))?;
            report.show(&source_text(&config, source));
            Ok(())
        }
        SourceCommand::Remove(NameWriteArgs { name, write }) => {
            let summary = format!("[source.{name}] removed");
            apply(ctx, write.dry_run, report, &summary, |doc| doc.remove_source(name))?;
            Ok(())
        }
    }
}

/// The source a `source add` form describes and its `cache`. Secret references are
/// parsed here, so a secret given by mistake is refused without being shown or written.
fn new_source(add: &SourceAddCommand) -> anyhow::Result<(&str, NewSource, bool, WriteArgs)> {
    Ok(match add {
        SourceAddCommand::Github(args) => (&args.name, github(args)?, !args.no_cache, args.write),
        SourceAddCommand::Gitlab(args) => {
            let token = secret_ref("--token", &args.token)?;
            (&args.name, NewSource::Gitlab { host: args.host.clone(), token }, !args.no_cache, args.write)
        }
        SourceAddCommand::Forgejo(args) | SourceAddCommand::Gitea(args) => {
            let token = secret_ref("--token", &args.token)?;
            let gitea = matches!(add, SourceAddCommand::Gitea(_));
            let new = NewSource::Forgejo { gitea, host: args.host.clone(), token };
            (&args.name, new, !args.no_cache, args.write)
        }
        SourceAddCommand::Helper(args) => {
            (&args.name, NewSource::Helper { helper: args.helper.clone() }, true, args.write)
        }
    })
}

/// `source add github`: the options that belong to `--auth`, and no others.
fn github(args: &GithubSourceArgs) -> anyhow::Result<NewSource> {
    let only = |used: bool, flag: &str, auth: &str| {
        if used { Err(anyhow::anyhow!("{flag} is only used with --auth {auth}")) } else { Ok(()) }
    };
    if args.auth != GithubAuth::Pat {
        only(args.token.is_some(), "--token", "pat")?;
    }
    if args.auth == GithubAuth::Gh && args.no_cache {
        bail!("--no-cache is only used with --auth pat or app: the bridge caches no gh tokens");
    }
    if args.auth != GithubAuth::App {
        only(args.app_id.is_some(), "--app-id", "app")?;
        only(args.private_key.is_some(), "--private-key", "app")?;
        only(!args.max_permissions.is_empty(), "--max-permission", "app")?;
        only(args.api_url.is_some(), "--api-url", "app")?;
    }
    let host = args.host.clone();
    Ok(match args.auth {
        GithubAuth::Gh => NewSource::GithubGh { host },
        GithubAuth::Pat => {
            let token = args.token.as_deref().context("--auth pat needs --token REFERENCE")?;
            NewSource::GithubPat { host, token: secret_ref("--token", token)? }
        }
        GithubAuth::App => {
            let app_id =
                args.app_id.context("--auth app needs --app-id ID, or --create to make a new App")?;
            let private_key =
                args.private_key.as_deref().context("--auth app needs --private-key REFERENCE")?;
            let max_permissions = parse_permission_list("--max-permission", &args.max_permissions)?;
            if max_permissions.is_empty() {
                bail!("--auth app needs --max-permission NAME=ACCESS, e.g. contents=write");
            }
            NewSource::GithubApp {
                host,
                api_url: args.api_url.clone(),
                app_id,
                private_key: secret_ref("--private-key", private_key)?,
                max_permissions,
            }
        }
    })
}

/// Whether `source test` has something to resolve: a secret reference, or a gh login.
fn resolves_something(source: &Source) -> bool {
    !matches!(source.kind, SourceKind::Helper { .. })
}

/// The label of a check of `source`: the key of its reference, or `gh`.
fn check_label(source: &Source) -> &'static str {
    match source.kind {
        SourceKind::GithubApp { .. } => "private_key",
        SourceKind::GithubGh { .. } => "gh",
        _ => "token",
    }
}

/// Asks the daemon to resolve what source `name` reads (control request `SourceTest`).
/// Only outcomes come back, never a secret. A daemon without the source (it has not
/// loaded the file as it is) gives no checks, as one with a helper by that name.
fn test_source(ctx: &Context, config: &Config, name: &str) -> Result<Vec<SourceCheck>, ControlError> {
    let daemon = daemon_config(ctx, Some(config));
    let mut client = connect(&daemon, SLOW_CONTROL_TIMEOUT)?;
    match client.request(&Request::SourceTest { source: name.to_owned() }) {
        Ok(Response::SourceTested(checks)) => Ok(checks),
        Err(ControlError::Daemon(error)) if error.kind == WorkerErrorKind::NotFound => Ok(Vec::new()),
        Ok(_) => Err(ControlError::Unexpected),
        Err(error) => Err(error),
    }
}

/// One report line per check; a failure gets `failed` as its status.
fn check_lines(source: &Source, checks: &[SourceCheck], failed: Status) -> Vec<Line> {
    let label = check_label(source);
    checks
        .iter()
        .map(|check| {
            let what = printable(&check.what);
            match &check.error {
                None => Line::ok(label, format!("{what}: resolved (the value is not shown)")),
                Some(error) => Line::new(failed, label, format!("{what}: {}", printable(&error.message))),
            }
        })
        .collect()
}

/// `source test NAME`: resolves the source's secret reference (or checks its gh login)
/// through the daemon. A helper source has nothing to resolve ahead of a request.
fn source_test(ctx: &Context, name: &str, report: &mut Report) -> anyhow::Result<()> {
    let config = load_config(ctx)?;
    let source = config.sources.get(name).with_context(|| format!("no [source.{name}]"))?;
    if !resolves_something(source) {
        report.push(
            Line::ok("helper", "nothing to resolve: the helper is asked per repository")
                .with_hint("try a URL with: credential-bridge-ctl server token SERVER URL"),
        );
        return Ok(());
    }
    let checks = test_source(ctx, &config, name)?;
    if checks.is_empty() {
        bail!("{} ({RELOAD_HINT})", nothing_to_resolve(name));
    }
    let lines = check_lines(source, &checks, Status::Fail);
    let failed = lines.iter().filter(|line| line.status == Status::Fail).count();
    for line in lines {
        report.push(line);
    }
    if failed > 0 {
        bail!("source {name} does not work yet: {failed} of {} check(s) failed", checks.len());
    }
    Ok(())
}

/// Why a source that resolves something got no checks: the daemon's configuration has
/// another kind of source by that name (a helper).
fn nothing_to_resolve(name: &str) -> String {
    format!("the daemon's configuration has nothing to resolve for source {name}; it may not have reloaded")
}

/// After `source add`: the same test, with failures as warnings (the entry stays).
pub(crate) fn test_after_add(ctx: &Context, config: &Config, name: &str, report: &mut Report) {
    let Some(source) = config.sources.get(name) else { return };
    let again = format!("credential-bridge-ctl source test {name}");
    match test_source(ctx, config, name) {
        Ok(checks) if checks.is_empty() => report.push(
            Line::warn(check_label(source), format!("not tested: {}", nothing_to_resolve(name)))
                .with_hint(format!("{RELOAD_HINT}, then {again}")),
        ),
        Ok(checks) => {
            let mut lines = check_lines(source, &checks, Status::Warn);
            if let Some(last) = lines.iter_mut().rev().find(|line| line.status == Status::Warn) {
                last.hint = Some(format!("the source is written; fix this and run {again}"));
            }
            for line in lines {
                report.push(line);
            }
        }
        Err(ControlError::NotRunning(_)) => report
            .push(Line::warn(check_label(source), "not tested: the daemon is not running").with_hint(again)),
        Err(error) => {
            report.push(Line::warn(check_label(source), format!("not tested: {error}")).with_hint(again))
        }
    }
}

/// The rules (`profile.git[i]`) that use `source`.
fn users(config: &Config, source: &str) -> Vec<String> {
    let profiles = config.profiles.values().chain(std::iter::once(&config.unregistered));
    profiles
        .flat_map(|profile| {
            profile
                .git
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.source == source)
                .map(move |(index, _)| format!("{}.git[{index}]", profile.name))
        })
        .collect()
}

/// The table `source list` prints.
fn source_table(config: &Config) -> String {
    if config.sources.is_empty() {
        return "no sources; add one with: credential-bridge-ctl source add github NAME\n".to_owned();
    }
    let width = config.sources.keys().map(String::len).max().unwrap_or(0).max(6);
    let kind_width = config.sources.values().map(|s| kind_cell(s).len()).max().unwrap_or(0).max(4);
    let host_width =
        config.sources.values().map(|s| s.kind.host().unwrap_or("any").len()).max().unwrap_or(0).max(4);
    let mut out =
        format!("{:<width$}  {:<kind_width$}  {:<host_width$}  USED BY\n", "SOURCE", "KIND", "HOST");
    for source in config.sources.values() {
        let users = users(config, &source.name);
        let used = if users.is_empty() { "no rule".to_owned() } else { users.join(", ") };
        out.push_str(&format!(
            "{:<width$}  {:<kind_width$}  {:<host_width$}  {used}\n",
            source.name,
            kind_cell(source),
            source.kind.host().unwrap_or("any")
        ));
    }
    out
}

/// The KIND cell of `source list`: the kind, `, no cache` with `cache = false`.
fn kind_cell(source: &Source) -> String {
    let kind = source.kind.describe();
    if source.cache { kind.to_owned() } else { format!("{kind}, no cache") }
}

/// What `source show` prints for `cache`, `None` for kinds the bridge caches nothing of.
fn cache_text(source: &Source) -> Option<&'static str> {
    if !source.kind.cached_by_bridge() {
        return None;
    }
    Some(match (&source.kind, source.cache) {
        (_, true) => "true",
        (SourceKind::GithubApp { .. }, false) => {
            "false: every request reads the private key and mints a new token"
        }
        (_, false) => "false: every request reads the vault again",
    })
}

/// What `source show` prints. References are shown; they hold no secret.
fn source_text(config: &Config, source: &Source) -> String {
    let mut out = format!("source           {}\nkind             {}\n", source.name, source.kind.describe());
    if let Some(host) = source.kind.host() {
        out.push_str(&format!("host             {host}\n"));
    }
    match &source.kind {
        SourceKind::GithubPat { token, .. }
        | SourceKind::GitlabToken { token, .. }
        | SourceKind::ForgejoToken { token, .. } => out.push_str(&format!("token            {token}\n")),
        SourceKind::GithubApp { api_url, app_id, private_key, max_permissions, .. } => {
            let permissions: Vec<String> =
                max_permissions.iter().map(|(name, access)| format!("{name}={}", access.as_str())).collect();
            out.push_str(&format!(
                "api_url          {api_url}\napp_id           {app_id}\nprivate_key      {private_key}\n\
                 max_permissions  {}\n",
                permissions.join(", ")
            ));
        }
        SourceKind::Helper { helper } => out.push_str(&format!("helper           {helper}\n")),
        SourceKind::GithubGh { .. } => out.push_str("token            from gh auth git-credential\n"),
    }
    if let Some(cache) = cache_text(source) {
        out.push_str(&format!("cache            {cache}\n"));
    }
    let users = users(config, &source.name);
    out.push_str(&format!(
        "used by          {}\n",
        if users.is_empty() { "no rule".to_owned() } else { users.join(", ") }
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{HelperSourceArgs, TokenSourceArgs};
    use credential_bridge_proto::ipc::{WorkerError, WorkerErrorKind};

    use crate::commands::test_support::{context, fake_daemon, recording_daemon, write_config};

    const TEXT: &str = "version = 2\n\n# where tokens come from\n[source.github]\ntype = \"github\"\nauth = \"gh\"\n\n\
                        [profile.dev]\n\n[[profile.dev.git]]\nurl = \"https://github.com/*\"\nsource = \"github\"\n";

    fn run(ctx: &Context, command: SourceCommand) -> anyhow::Result<Report> {
        let mut report = Report::default();
        source(ctx, &command, &mut report).map(|()| report)
    }

    fn github(name: &str, auth: GithubAuth) -> GithubSourceArgs {
        GithubSourceArgs {
            name: name.into(),
            auth,
            host: None,
            token: None,
            app_id: None,
            private_key: None,
            max_permissions: Vec::new(),
            api_url: None,
            no_cache: false,
            create: false,
            org: None,
            app_name: None,
            public: false,
            write: WriteArgs::default(),
        }
    }

    fn token(name: &str, token: &str) -> TokenSourceArgs {
        TokenSourceArgs {
            name: name.into(),
            host: "git.example.com".into(),
            token: token.into(),
            no_cache: false,
            write: WriteArgs::default(),
        }
    }

    fn text(ctx: &Context) -> String {
        std::fs::read_to_string(&ctx.config_path).unwrap()
    }

    #[test]
    fn every_kind_round_trips() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut pat = github("ci", GithubAuth::Pat);
        pat.token = Some("op://CI/github/credential".into());
        let mut app = github("app", GithubAuth::App);
        app.app_id = Some(42);
        app.private_key = Some("keepassxc://Dev/app/key".into());
        app.max_permissions = vec!["contents=write".into(), "pull_requests=read".into()];
        let mut ghes = github("ghes", GithubAuth::Gh);
        ghes.host = Some("github.example.com".into());
        for command in [
            SourceAddCommand::Github(pat),
            SourceAddCommand::Github(app),
            SourceAddCommand::Github(ghes),
            SourceAddCommand::Gitlab(token("gitlab", "bw://gitlab/token")),
            SourceAddCommand::Forgejo(token("forgejo", "pass://forge/token")),
            SourceAddCommand::Gitea(token("gitea", "cmd:cat ~/token")),
            SourceAddCommand::Helper(HelperSourceArgs {
                name: "helper".into(),
                helper: "manager".into(),
                write: WriteArgs::default(),
            }),
        ] {
            run(&ctx, SourceCommand::Add(command)).unwrap();
        }
        let text = text(&ctx);
        assert!(text.starts_with(TEXT.split("\n\n[profile").next().unwrap()), "{text}");
        assert!(text.contains("# where tokens come from\n[source.github]"));
        assert!(text.contains(
            "[source.app]\ntype = \"github\"\nauth = \"app\"\napp_id = 42\nprivate_key = \"keepassxc://Dev/app/key\"\n\
             max_permissions = { contents = \"write\", pull_requests = \"read\" }\n"
        ));
        let config = load_config(&ctx).unwrap();
        assert_eq!(config.sources.len(), 8);
        let list = run(&ctx, SourceCommand::List).unwrap().text;
        assert!(list.contains("github   github (gh)      github.com          dev.git[0]"), "{list}");
        assert!(list.contains("helper   helper           any                 no rule"), "{list}");
        let show = run(&ctx, SourceCommand::Show(NameArg { name: "app".into() })).unwrap().text;
        assert!(show.contains("max_permissions  contents=write, pull_requests=read"), "{show}");
    }

    #[test]
    fn no_cache_is_written_and_shown() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut pat = github("prod", GithubAuth::Pat);
        pat.token = Some("op://Prod/github/credential".into());
        pat.no_cache = true;
        let mut app = github("app", GithubAuth::App);
        app.app_id = Some(42);
        app.private_key = Some("op://Dev/app/key".into());
        app.max_permissions = vec!["contents=read".into()];
        app.no_cache = true;
        let mut gitlab = token("gitlab", "bw://gitlab/token");
        gitlab.no_cache = true;
        for command in [
            SourceAddCommand::Github(pat),
            SourceAddCommand::Github(app),
            SourceAddCommand::Gitlab(gitlab),
            SourceAddCommand::Forgejo(token("forgejo", "pass://forge/token")),
        ] {
            run(&ctx, SourceCommand::Add(command)).unwrap();
        }
        let text = text(&ctx);
        assert!(
            text.contains("[source.prod]\ntype = \"github\"\nauth = \"pat\"\ntoken = \"op://Prod/github/credential\"\ncache = false\n"),
            "{text}"
        );
        assert_eq!(text.matches("cache = false").count(), 3, "{text}");
        let config = load_config(&ctx).unwrap();
        assert!(
            !config.sources["app"].cache
                && !config.sources["gitlab"].cache
                && config.sources["forgejo"].cache
        );

        let list = run(&ctx, SourceCommand::List).unwrap().text;
        assert!(list.contains("prod     github (pat), no cache    github.com"), "{list}");
        assert!(list.contains("forgejo  forgejo (token)           git.example.com"), "{list}");
        let show = |name: &str| run(&ctx, SourceCommand::Show(NameArg { name: name.into() })).unwrap().text;
        assert!(show("prod").contains("cache            false: every request reads the vault again\n"));
        assert!(
            show("app").contains(
                "cache            false: every request reads the private key and mints a new token\n"
            )
        );
        assert!(show("forgejo").contains("cache            true\n"));
        assert!(!show("github").contains("cache"), "gh keeps no token in the bridge");

        // gh caches nothing in the bridge.
        let mut gh = github("gh2", GithubAuth::Gh);
        gh.no_cache = true;
        let error = run(&ctx, SourceCommand::Add(SourceAddCommand::Github(gh))).unwrap_err().to_string();
        assert!(error.contains("--no-cache is only used with --auth pat or app"), "{error}");
    }

    #[test]
    fn secrets_are_refused_and_never_shown() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let mut pat = github("ci", GithubAuth::Pat);
        pat.token = Some("ghp_ThisIsAPlainTokenNotAReference".into());
        let message = run(&ctx, SourceCommand::Add(SourceAddCommand::Github(pat))).unwrap_err().to_string();
        assert!(message.contains("--token takes a reference") && !message.contains("ghp_"), "{message}");
        let error =
            run(&ctx, SourceCommand::Add(SourceAddCommand::Gitlab(token("gl", "glpat-secret")))).unwrap_err();
        assert!(!error.to_string().contains("glpat"), "{error}");
        let mut gh = github("x", GithubAuth::Gh);
        gh.token = Some("op://a/b/c".into());
        assert!(
            run(&ctx, SourceCommand::Add(SourceAddCommand::Github(gh)))
                .unwrap_err()
                .to_string()
                .contains("only used with --auth pat")
        );
        assert_eq!(text(&ctx), TEXT);
    }

    #[test]
    fn remove_refuses_sources_in_use() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let remove = |name: &str, dry_run| {
            SourceCommand::Remove(NameWriteArgs { name: name.into(), write: WriteArgs { dry_run } })
        };
        let message = format!("{:#}", run(&ctx, remove("github", false)).unwrap_err());
        assert!(message.contains("profile.dev.git[0] (https://github.com/*)"), "{message}");
        assert!(
            message.contains("credential-bridge-ctl profile rule remove dev 'https://github.com/*'"),
            "{message}"
        );
        run(&ctx, SourceCommand::Add(SourceAddCommand::Gitlab(token("gl", "bw://a/b")))).unwrap();
        let report = run(&ctx, remove("gl", true)).unwrap();
        assert!(report.text.contains("-[source.gl]\n"), "{}", report.text);
        assert!(text(&ctx).contains("[source.gl]"));
        run(&ctx, remove("gl", false)).unwrap();
        assert_eq!(text(&ctx), TEXT);
    }

    const GITLAB: &str = "version = 2\n\n[source.gl]\ntype = \"gitlab\"\nhost = \"gitlab.example.com\"\n\
                          token = \"bw://gitlab/token\"\n\n[source.mgr]\ntype = \"helper\"\nhelper = \"manager\"\n";

    fn tested(error: Option<WorkerError>) -> Response {
        Response::SourceTested(vec![SourceCheck { what: "bw://gitlab/token".into(), error }])
    }

    fn test(ctx: &Context, name: &str) -> anyhow::Result<Report> {
        let mut report = Report::default();
        match source(ctx, &SourceCommand::Test(NameArg { name: name.into() }), &mut report) {
            Ok(()) => Ok(report),
            Err(error) => Err(error.context(report.text)),
        }
    }

    #[test]
    fn test_resolves_through_the_daemon_and_never_shows_the_secret() {
        let (_dir, ctx) = context();
        write_config(&ctx, GITLAB);
        let requests = recording_daemon(&ctx.paths.control_socket, tested(None));
        let report = test(&ctx, "gl").unwrap();
        assert_eq!(
            report.text,
            "✓ token                bw://gitlab/token: resolved (the value is not shown)\n"
        );
        assert_eq!(*requests.lock().unwrap(), vec![Request::SourceTest { source: "gl".into() }]);
        // The response type has no room for a value: only the reference and an error.
        assert!(!report.text.contains("glpat"));
    }

    #[test]
    fn test_reports_a_locked_vault_and_a_missing_item() {
        for (kind, message) in [
            (
                WorkerErrorKind::Locked,
                "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden",
            ),
            (WorkerErrorKind::NotFound, "bw://gitlab/token not found"),
        ] {
            let (_dir, ctx) = context();
            write_config(&ctx, GITLAB);
            fake_daemon(&ctx.paths.control_socket, tested(Some(WorkerError::new(kind, message))));
            let error = format!("{:#}", test(&ctx, "gl").unwrap_err());
            assert!(
                error.contains(&format!("✗ token                bw://gitlab/token: {message}")),
                "{error}"
            );
            assert!(error.contains("source gl does not work yet: 1 of 1 check(s) failed"), "{error}");
        }
    }

    #[test]
    fn test_of_a_helper_or_without_daemon() {
        let (_dir, ctx) = context();
        write_config(&ctx, GITLAB);
        let report = test(&ctx, "mgr").unwrap();
        assert!(
            report.text.contains("nothing to resolve: the helper is asked per repository"),
            "{}",
            report.text
        );
        let error = format!("{:#}", test(&ctx, "gl").unwrap_err());
        assert!(error.contains("the daemon is not running"), "{error}");
        assert!(format!("{:#}", test(&ctx, "nope").unwrap_err()).contains("no [source.nope]"));
    }

    /// `source add` tests the new source; a failure is a warning and the entry stays.
    #[test]
    fn add_tests_the_new_source() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let locked = WorkerError::new(
            WorkerErrorKind::Locked,
            "vault bitwarden is locked: run credential-bridge-ctl vault unlock bitwarden",
        );
        let requests = recording_daemon(&ctx.paths.control_socket, tested(Some(locked)));
        let mut dry = token("gl", "bw://gitlab/token");
        dry.write.dry_run = true;
        run(&ctx, SourceCommand::Add(SourceAddCommand::Gitlab(dry))).unwrap();
        assert!(requests.lock().unwrap().is_empty(), "a dry run tests nothing");

        let report =
            run(&ctx, SourceCommand::Add(SourceAddCommand::Gitlab(token("gl", "bw://gitlab/token"))))
                .unwrap();
        assert!(text(&ctx).contains("[source.gl]"));
        assert!(
            report.text.contains("⚠ token                bw://gitlab/token: vault bitwarden is locked"),
            "{}",
            report.text
        );
        assert!(
            report
                .text
                .contains("→ the source is written; fix this and run credential-bridge-ctl source test gl")
        );
        assert!(!report.failed());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![Request::Reload, Request::SourceTest { source: "gl".into() }]
        );

        // A helper has nothing to test.
        let helper =
            HelperSourceArgs { name: "mgr".into(), helper: "manager".into(), write: WriteArgs::default() };
        run(&ctx, SourceCommand::Add(SourceAddCommand::Helper(helper))).unwrap();
        assert_eq!(requests.lock().unwrap().last(), Some(&Request::Reload));
    }

    /// A daemon whose configuration has nothing to resolve for a source that resolves
    /// something, or no such source at all, has not reloaded: `source test` fails, after `source add` it is a
    /// warning.
    #[test]
    fn nothing_tested_means_the_daemon_did_not_reload() {
        let missing =
            WorkerError::new(WorkerErrorKind::NotFound, "no source gl in the configuration the daemon uses");
        nothing_tested(Response::SourceTested(Vec::new()));
        nothing_tested(Response::Error(missing));
    }

    /// [`nothing_tested_means_the_daemon_did_not_reload`] with the daemon answering
    /// `answer` (also to the reload of `source add`).
    fn nothing_tested(answer: Response) {
        let (_dir, ctx) = context();
        write_config(&ctx, GITLAB);
        fake_daemon(&ctx.paths.control_socket, answer);
        let error = format!("{:#}", test(&ctx, "gl").unwrap_err());
        assert!(
            error.contains(
                "the daemon's configuration has nothing to resolve for source gl; it may not have reloaded \
                 (credential-bridge-ctl daemon reload)"
            ),
            "{error}"
        );

        let report =
            run(&ctx, SourceCommand::Add(SourceAddCommand::Forgejo(token("fj", "bw://forge/token"))))
                .unwrap();
        assert!(
            report.text.contains(
                "⚠ token                not tested: the daemon's configuration has nothing to resolve for source fj"
            ),
            "{}",
            report.text
        );
        assert!(
            report
                .text
                .contains("→ credential-bridge-ctl daemon reload, then credential-bridge-ctl source test fj"),
            "{}",
            report.text
        );
        assert!(!report.failed());
    }

    /// The hint goes to the last failing check, not to a check that worked.
    #[test]
    fn add_hints_at_the_last_failing_check() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let missing = WorkerError::new(WorkerErrorKind::NotFound, "op://Dev/app/key not found");
        fake_daemon(
            &ctx.paths.control_socket,
            Response::SourceTested(vec![
                SourceCheck { what: "op://Dev/app/key".into(), error: Some(missing) },
                SourceCheck { what: "op://Dev/app/other".into(), error: None },
            ]),
        );
        let mut app = github("app", GithubAuth::App);
        app.app_id = Some(42);
        app.private_key = Some("op://Dev/app/key".into());
        app.max_permissions = vec!["contents=write".into()];
        let report = run(&ctx, SourceCommand::Add(SourceAddCommand::Github(app))).unwrap();
        let checks: Vec<&Line> = report.lines.iter().filter(|line| line.label == "private_key").collect();
        assert_eq!(checks.len(), 2, "{}", report.text);
        assert_eq!(
            checks[0].hint.as_deref(),
            Some("the source is written; fix this and run credential-bridge-ctl source test app")
        );
        assert_eq!(checks[1].hint, None);
    }

    #[test]
    fn add_without_daemon_says_it_did_not_test() {
        let (_dir, ctx) = context();
        write_config(&ctx, TEXT);
        let report =
            run(&ctx, SourceCommand::Add(SourceAddCommand::Gitlab(token("gl", "bw://gitlab/token"))))
                .unwrap();
        assert!(
            report.text.contains("⚠ token                not tested: the daemon is not running"),
            "{}",
            report.text
        );
        assert!(report.text.contains("→ credential-bridge-ctl source test gl"), "{}", report.text);
    }
}
