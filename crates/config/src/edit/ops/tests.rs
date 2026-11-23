use std::path::Path;

use credential_bridge_proto::ipc::git::{Access, TokenScope};

use super::*;
use crate::paths::{PathVars, Paths, TargetOs};
use crate::{Config, Confirm, KeySelection, SocketSpec, SourceKind};

fn paths(home: &Path) -> Paths {
    let vars = PathVars { home: Some(home.as_os_str().to_owned()), ..PathVars::default() };
    Paths::from_vars(&vars, TargetOs::Linux).unwrap()
}

/// A hand-written file with comments and alignment that every edit must keep.
const HAND: &str = r#"# my configuration
version = 2

[agent]
add_to = "fido"                     # ssh-add goes here

# the agents
[[agent.upstream]]
name   = "fido"
socket = "~/.ssh/agent.sock"

[[agent.upstream]]
name   = "yubikey"                  # OpenPGP card
socket = "gpgconf:agent-ssh-socket"

[source.github]                     # gh is logged in
type = "github"
auth = "gh"

# build servers
[profile.build]
ssh  = { keys = ["yubikey"] }       # only the card

[[profile.build.git]]
url    = "https://github.com/my-org/*"
source = "github"

[profile.dev]
ssh = { keys = "all", confirm = "8h" }   # dialog
"#;

/// Opens `text` as a document in a fresh directory.
fn open(text: &str) -> (tempfile::TempDir, ConfigDocument) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    let doc = ConfigDocument::open(&path).unwrap();
    (dir, doc)
}

/// Validates the document like the daemon.
fn valid(dir: &tempfile::TempDir, doc: &ConfigDocument) -> Config {
    doc.check(&paths(dir.path())).unwrap_or_else(|error| panic!("{error}\n{}", doc.to_text()))
}

/// Every line of `HAND` that contains a comment is still there.
fn keeps_comments(text: &str) {
    for line in HAND.lines().filter(|line| line.contains('#')) {
        assert!(text.contains(line), "lost {line:?} in:\n{text}");
    }
}

fn setting(text: &str) -> ProfileSetting {
    ProfileSetting::parse(text).unwrap()
}

fn token(text: &str) -> SecretRef {
    text.parse().unwrap()
}

#[test]
fn original_text_is_kept() {
    let (_dir, doc) = open(HAND);
    assert_eq!(doc.original_text(), Some(HAND));
    let dir = tempfile::tempdir().unwrap();
    let doc = ConfigDocument::open(&dir.path().join("missing.toml")).unwrap();
    assert_eq!(doc.original_text(), None);
}

#[test]
fn upstreams() {
    let (dir, mut doc) = open(HAND);
    doc.add_upstream("1password", "~/.1password/agent.sock").unwrap();
    assert!(matches!(doc.add_upstream("fido", "/x"), Err(EditError::Exists { .. })));
    let text = doc.to_text();
    keeps_comments(&text);
    assert!(
        text.contains("socket = \"gpgconf:agent-ssh-socket\"\n\n[[agent.upstream]]\nname = \"1password\"\n"),
        "{text}"
    );
    let config = valid(&dir, &doc);
    let names: Vec<&str> =
        config.agent.as_ref().unwrap().upstreams.iter().map(|upstream| upstream.name.as_str()).collect();
    assert_eq!(names, ["fido", "yubikey", "1password"]);

    doc.set_upstream_socket("1password", "/run/op.sock").unwrap();
    doc.set_add_to(Some("1password")).unwrap();
    assert!(doc.to_text().contains("add_to = \"1password\"                     # ssh-add goes here"));
    assert!(matches!(doc.set_add_to(Some("nope")), Err(EditError::NotFound { .. })));
    let config = valid(&dir, &doc);
    assert_eq!(config.agent.as_ref().unwrap().upstreams[2].socket, SocketSpec::Path("/run/op.sock".into()));

    doc.remove_upstream("fido").unwrap();
    assert!(!doc.to_text().contains("\"fido\""));
    valid(&dir, &doc);
    assert!(matches!(doc.remove_upstream("fido"), Err(EditError::NotFound { .. })));
}

#[test]
fn upstreams_in_use_are_not_removed() {
    let (_dir, mut doc) = open(HAND);
    match doc.remove_upstream("yubikey") {
        Err(EditError::InUse { users, fixes, .. }) => {
            assert_eq!(users, ["profile.build.ssh.keys"]);
            assert_eq!(fixes, ["credential-bridge-ctl profile set build ssh.keys=none"]);
        }
        other => panic!("{other:?}"),
    }
    let error = doc.remove_upstream("fido").unwrap_err();
    assert!(matches!(&error, EditError::InUse { users, .. } if users == &["agent.add_to"]), "{error:?}");
    assert!(error.to_string().contains("agent set --add-to"), "{error}");
    assert_eq!(doc.to_text(), HAND);
}

#[test]
fn first_upstream_in_an_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = ConfigDocument::open(&dir.path().join("config.toml")).unwrap();
    doc.add_upstream("main", "~/agents/main.sock").unwrap();
    doc.set_add_to(Some("main")).unwrap();
    assert_eq!(
        doc.to_text(),
        "version = 2\n\n[agent]\nadd_to = \"main\"\n\n[[agent.upstream]]\nname = \"main\"\nsocket = \"~/agents/main.sock\"\n"
    );
    valid(&dir, &doc);
    doc.set_add_to(None).unwrap();
    doc.remove_upstream("main").unwrap();
    assert_eq!(doc.to_text(), "version = 2\n");
}

#[test]
fn a_written_agent_header_stays() {
    let text = "version = 2\n\n# my agents\n[agent]\n";
    let (dir, mut doc) = open(text);
    doc.add_upstream("a", "/a.sock").unwrap();
    assert_eq!(doc.to_text(), format!("{text}\n[[agent.upstream]]\nname = \"a\"\nsocket = \"/a.sock\"\n"));
    valid(&dir, &doc);
    // Implicit parents stay implicit when a value lands below them.
    let (dir, mut doc) = open("version = 2\n\n[vault.keepassxc]\ndatabase = \"/db.kdbx\"\n");
    doc.set_keepassxc(KeepassxcKey::KeyFile, Some("/k")).unwrap();
    assert!(!doc.to_text().contains("[vault]\n"));
    valid(&dir, &doc);
}

#[test]
fn sources_of_every_kind() {
    let (dir, mut doc) = open(HAND);
    let max: Permissions = [("contents".to_owned(), Access::Write)].into();
    let sources = [
        ("ghes", NewSource::GithubGh { host: Some("github.example.com".into()) }),
        ("ci", NewSource::GithubPat { host: None, token: token("op://CI/github/credential") }),
        (
            "app",
            NewSource::GithubApp {
                host: Some("github.com".into()),
                api_url: None,
                app_id: 7,
                private_key: token("op://Dev/app/key"),
                max_permissions: max.clone(),
            },
        ),
        (
            "gitlab",
            NewSource::Gitlab { host: "gitlab.example.com".into(), token: token("bw://gitlab/token") },
        ),
        (
            "forgejo",
            NewSource::Forgejo { gitea: false, host: "codeberg.org".into(), token: token("pass://forge") },
        ),
        (
            "gitea",
            NewSource::Forgejo { gitea: true, host: "gitea.example.com".into(), token: token("cmd:t") },
        ),
        ("helper", NewSource::Helper { helper: "manager".into() }),
    ];
    for (name, source) in &sources {
        doc.add_source(name, source).unwrap();
    }
    assert!(matches!(doc.add_source("github", &sources[0].1), Err(EditError::Exists { .. })));
    let text = doc.to_text();
    keeps_comments(&text);
    assert!(text.contains(
        "[source.app]\ntype = \"github\"\nauth = \"app\"\napp_id = 7\nprivate_key = \"op://Dev/app/key\"\n\
         max_permissions = { contents = \"write\" }\n"
    ));
    assert!(text.contains(
        "[source.gitea]\ntype = \"gitea\"\nhost = \"gitea.example.com\"\nauth = \"token\"\ntoken = \"cmd:t\"\n"
    ));
    // New sources come after the existing ones, before the profiles.
    assert!(text.find("[source.helper]").unwrap() < text.find("# build servers").unwrap(), "{text}");
    let config = valid(&dir, &doc);
    assert!(
        matches!(&config.sources["ghes"].kind, SourceKind::GithubGh { host } if host == "github.example.com")
    );
    assert!(matches!(config.sources["ci"].kind, SourceKind::GithubPat { .. }));
    assert!(matches!(config.sources["app"].kind, SourceKind::GithubApp { app_id: 7, .. }));
    assert!(matches!(config.sources["gitlab"].kind, SourceKind::GitlabToken { .. }));
    assert!(matches!(config.sources["forgejo"].kind, SourceKind::ForgejoToken { .. }));
    assert!(matches!(config.sources["gitea"].kind, SourceKind::ForgejoToken { .. }));
    assert!(matches!(config.sources["helper"].kind, SourceKind::Helper { .. }));

    doc.remove_source("helper").unwrap();
    assert!(!doc.to_text().contains("[source.helper]"));
    assert!(matches!(doc.remove_source("helper"), Err(EditError::NotFound { .. })));
}

#[test]
fn source_cache() {
    let (dir, mut doc) = open(HAND);
    doc.add_source("ci", &NewSource::GithubPat { host: None, token: token("op://CI/github/credential") })
        .unwrap();
    doc.set_source_cache("ci", false).unwrap();
    assert!(doc.to_text().contains("[source.ci]\ntype = \"github\"\nauth = \"pat\"\ntoken = \"op://CI/github/credential\"\ncache = false\n"));
    assert!(!valid(&dir, &doc).sources["ci"].cache);
    doc.set_source_cache("ci", true).unwrap();
    assert!(!doc.to_text().contains("cache"));
    assert!(valid(&dir, &doc).sources["ci"].cache);
    assert!(matches!(doc.set_source_cache("nope", false), Err(EditError::NotFound { .. })));

    // gh keeps no token in the bridge: the document no longer validates.
    doc.set_source_cache("github", false).unwrap();
    let error = doc.check(&paths(dir.path())).unwrap_err().to_string();
    assert!(error.contains("the bridge caches no tokens of gh and helper sources"), "{error}");
}

#[test]
fn sources_in_use_are_not_removed() {
    let (_dir, mut doc) = open(HAND);
    match doc.remove_source("github") {
        Err(EditError::InUse { users, fixes, .. }) => {
            assert_eq!(users, ["profile.build.git[0] (https://github.com/my-org/*)"]);
            assert_eq!(
                fixes,
                ["credential-bridge-ctl profile rule remove build 'https://github.com/my-org/*'"]
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(doc.to_text(), HAND);
}

#[test]
fn profile_settings_parse_and_check_values() {
    for (text, value) in [
        ("ssh.keys=all", "\"all\""),
        ("ssh.keys=none", "[]"),
        ("ssh.keys=fido,yubikey,fido", "[\"fido\", \"yubikey\"]"),
        ("ssh.confirm=8h", "\"8h\""),
        ("ssh.confirm=always", "\"always\""),
        ("hops.ssh=false", "false"),
        ("signing=ssh", "\"ssh\""),
        ("gpg=sign,decrypt", "[\"sign\", \"decrypt\"]"),
        ("gpg=none", "[]"),
    ] {
        assert_eq!(setting(text).value.to_string(), value, "{text}");
    }
    for (text, hint) in [
        ("ssh.keys", "KEY=VALUE"),
        ("ssh.key=all", "known keys: ssh.keys"),
        ("ssh.keys=a b", "not an upstream name"),
        ("ssh.keys=fido,all", "not an upstream name"),
        ("ssh.confirm=8", "a duration"),
        ("ssh.confirm=400d", "a duration"),
        ("hops.git=yes", "true or false"),
        ("signing=gpg", "ssh"),
        ("gpg=encrypt", "sign, decrypt"),
    ] {
        let error = ProfileSetting::parse(text).unwrap_err().to_string();
        assert!(error.contains(hint), "{text}: {error}");
    }
}

#[test]
fn profiles() {
    let (dir, mut doc) = open(HAND);
    doc.add_profile("ci").unwrap();
    assert!(matches!(doc.add_profile("dev"), Err(EditError::Exists { .. })));
    assert!(matches!(doc.add_profile("unregistered"), Err(EditError::Value { .. })));
    for text in ["ssh.keys=fido", "ssh.confirm=always", "hops.git=true", "gpg=sign"] {
        doc.set_profile("ci", &setting(text)).unwrap();
    }
    // Replacing a value keeps the comment after the table.
    doc.set_profile("build", &setting("ssh.keys=fido,yubikey")).unwrap();
    doc.set_profile("dev", &setting("ssh.confirm=always")).unwrap();
    let text = doc.to_text();
    keeps_comments(&text.replace("[\"fido\", \"yubikey\"]", "[\"yubikey\"]").replace("\"always\"", "\"8h\""));
    assert!(text.contains("[profile.ci]\nssh = { keys = [\"fido\"], confirm = \"always\" }\nhops = { git = true }\ngpg = [\"sign\"]\n"), "{text}");
    // A profile that allows gpg needs [gpg].
    let error = doc.check(&paths(dir.path())).unwrap_err().to_string();
    assert!(error.contains("there is no [gpg] table"), "{error}");
    doc.set_gpg(None).unwrap();
    assert!(doc.to_text().contains("[gpg]\n"));
    let config = valid(&dir, &doc);
    let ci = &config.profiles["ci"];
    assert_eq!(ci.ssh.as_ref().unwrap().keys, KeySelection::Upstreams(vec!["fido".into()]));
    assert_eq!(ci.ssh.as_ref().unwrap().confirm, Confirm::Always);
    assert!(ci.hops.git && ci.hops.ssh && ci.gpg.sign && !ci.gpg.decrypt);

    doc.unset_profile("ci", ProfileKey::HopsGit).unwrap();
    doc.unset_profile("ci", ProfileKey::Gpg).unwrap();
    doc.unset_profile("ci", ProfileKey::Signing).unwrap();
    assert!(doc.to_text().contains("[profile.ci]\nssh = { keys = [\"fido\"], confirm = \"always\" }\n"));
    assert!(matches!(doc.set_profile("nope", &setting("signing=ssh")), Err(EditError::NotFound { .. })));
    doc.remove_profile("ci").unwrap();
    assert!(!doc.to_text().contains("profile.ci"));
    assert!(matches!(doc.remove_profile("ci"), Err(EditError::NotFound { .. })));
}

#[test]
fn unregistered_allows_only_ssh() {
    let (dir, mut doc) = open(HAND);
    doc.unset_profile("unregistered", ProfileKey::SshKeys).unwrap();
    assert_eq!(doc.to_text(), HAND, "unsetting what is not written changes nothing");
    for text in ["signing=ssh", "gpg=sign", "hops.git=true", "hops.gpg=false"] {
        let error = doc.set_profile("unregistered", &setting(text)).unwrap_err().to_string();
        assert!(error.contains("allows only ssh.keys, ssh.confirm and hops.ssh"), "{error}");
    }
    doc.set_profile("unregistered", &setting("ssh.keys=fido")).unwrap();
    doc.set_profile("unregistered", &setting("hops.ssh=true")).unwrap();
    assert!(
        doc.to_text()
            .ends_with("[profile.unregistered]\nssh = { keys = [\"fido\"] }\nhops = { ssh = true }\n")
    );
    let config = valid(&dir, &doc);
    assert_eq!(config.unregistered.ssh.as_ref().unwrap().confirm, Confirm::Always);
    assert!(config.unregistered.hops.ssh);
    let rule = NewRule { url: "https://github.com/*".into(), source: "github".into(), ..rule() };
    assert!(matches!(doc.add_rule("unregistered", &rule, None), Err(EditError::Value { .. })));
    doc.remove_profile("unregistered").unwrap();
    assert_eq!(doc.to_text(), HAND);
}

fn rule() -> NewRule {
    NewRule { url: String::new(), source: String::new(), permissions: Permissions::new(), per: None }
}

#[test]
fn rules() {
    let (dir, mut doc) = open(HAND);
    let app = NewSource::GithubApp {
        host: None,
        api_url: None,
        app_id: 1,
        private_key: token("op://a/b/c"),
        max_permissions: [("contents".to_owned(), Access::Write)].into(),
    };
    doc.add_source("app", &app).unwrap();
    let owner = NewRule {
        url: "https://github.com/acme/*".into(),
        source: "app".into(),
        permissions: [("contents".to_owned(), Access::Read)].into(),
        per: Some(TokenScope::Owner),
    };
    doc.add_rule("build", &owner, None).unwrap();
    let first = NewRule { url: "https://github.com/my-org/app".into(), source: "github".into(), ..rule() };
    doc.add_rule("build", &first, Some("https://github.com/my-org/*")).unwrap();
    let dev = NewRule { url: "https://github.com/*".into(), source: "github".into(), ..rule() };
    doc.add_rule("dev", &dev, None).unwrap();
    let text = doc.to_text();
    keeps_comments(&text);
    assert!(matches!(doc.add_rule("build", &first, None), Err(EditError::Exists { .. })));
    assert!(matches!(doc.add_rule("build", &dev, Some("https://x/*")), Err(EditError::NotFound { .. })));
    let bad = NewRule { url: "github.com/*".into(), ..dev.clone() };
    assert!(matches!(doc.add_rule("dev", &bad, None), Err(EditError::Value { .. })));
    assert!(text.contains(
        "[[profile.build.git]]\nurl = \"https://github.com/acme/*\"\nsource = \"app\"\n\
         permissions = { contents = \"read\" }\nper = \"owner\"\n"
    ));
    let config = valid(&dir, &doc);
    let urls: Vec<&str> = config.profiles["build"].git.iter().map(|rule| rule.url.as_str()).collect();
    assert_eq!(
        urls,
        ["https://github.com/my-org/app", "https://github.com/my-org/*", "https://github.com/acme/*"]
    );
    assert_eq!(config.profiles["dev"].git.len(), 1);
    // The rule for dev sits under [profile.dev], not after it at the end of another table.
    assert!(text.find("[[profile.dev.git]]").unwrap() > text.find("[profile.dev]").unwrap());

    doc.remove_rule("build", "https://github.com/my-org/app").unwrap();
    doc.remove_rule("dev", "https://github.com/*").unwrap();
    assert!(matches!(doc.remove_rule("dev", "https://github.com/*"), Err(EditError::NotFound { .. })));
    assert!(!doc.to_text().contains("[[profile.dev.git]]"));
    valid(&dir, &doc);

    // Validation catches what the edit cannot see: a rule beyond max_permissions.
    let wide = NewRule {
        url: "https://github.com/wide/*".into(),
        permissions: [("contents".to_owned(), Access::Admin)].into(),
        per: None,
        ..owner
    };
    doc.add_rule("build", &wide, None).unwrap();
    let error = doc.check(&paths(dir.path())).unwrap_err().to_string();
    assert!(error.contains("exceeds max_permissions"), "{error}");
}

#[test]
fn servers_and_profiles_in_use() {
    let key = crate::test_support::test_key(1);
    let (dir, mut doc) = open(HAND);
    doc.set_server("box", &crate::edit::HostKeysEntry::Pinned(std::slice::from_ref(&key)), "build", true)
        .unwrap();
    let error = doc.remove_profile("build").unwrap_err();
    match &error {
        EditError::InUse { users, fixes, .. } => {
            assert_eq!(users, &["server.box"]);
            assert!(fixes[0].contains("server set box --profile OTHER"), "{fixes:?}");
        }
        other => panic!("{other:?}"),
    }
    doc.set_server_profile("box", "dev").unwrap();
    assert!(matches!(doc.set_server_profile("nope", "dev"), Err(EditError::NotFound { .. })));
    assert_eq!(valid(&dir, &doc).servers["box"].profile, "dev");
    doc.remove_profile("build").unwrap();
    valid(&dir, &doc);
}

#[test]
fn vault_gpg_daemon() {
    let (dir, mut doc) = open(HAND);
    doc.set_keepassxc(KeepassxcKey::Database, Some("~/db.kdbx")).unwrap();
    doc.set_keepassxc(KeepassxcKey::KeyFile, Some("/k.keyx")).unwrap();
    doc.set_gpg(Some(Some("gpgconf:agent-extra-socket"))).unwrap();
    // Without a socket the existing one stays; Some(None) removes it.
    doc.set_gpg(None).unwrap();
    assert!(doc.to_text().contains("[gpg]\nsocket = \"gpgconf:agent-extra-socket\"\n"));
    doc.set_gpg(Some(None)).unwrap();
    assert!(!doc.to_text().contains("socket = \"gpgconf:agent-extra-socket\""));
    doc.set_gpg(Some(Some("gpgconf:agent-extra-socket"))).unwrap();
    doc.set_daemon(DaemonKey::AuditLog, Some("~/audit.log")).unwrap();
    let text = doc.to_text();
    keeps_comments(&text);
    assert!(text.contains("[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\nkey_file = \"/k.keyx\"\n"), "{text}");
    assert!(!text.contains("[vault]\n"), "{text}");
    let config = valid(&dir, &doc);
    assert_eq!(config.vault.keepassxc.database, Some(dir.path().join("db.kdbx")));
    assert_eq!(config.daemon.audit_log, dir.path().join("audit.log"));
    assert!(config.gpg.is_some());

    // key_file needs database: the edit is fine, validation is not.
    doc.set_keepassxc(KeepassxcKey::Database, None).unwrap();
    assert!(doc.check(&paths(dir.path())).unwrap_err().to_string().contains("key_file needs database"));
    assert!(doc.remove_keepassxc());
    assert!(!doc.remove_keepassxc());
    doc.set_daemon(DaemonKey::AuditLog, None).unwrap();
    doc.set_profile("dev", &setting("gpg=sign")).unwrap();
    assert!(matches!(doc.remove_gpg(), Err(EditError::InUse { .. })));
    doc.unset_profile("dev", ProfileKey::Gpg).unwrap();
    assert!(doc.remove_gpg().unwrap());
    assert!(!doc.remove_gpg().unwrap());
    let text = doc.to_text();
    assert!(!text.contains("vault") && !text.contains("[gpg]"), "{text}");
    valid(&dir, &doc);
}

#[test]
fn inline_tables_are_edited_in_place_and_odd_layouts_refused() {
    let (dir, mut doc) = open("version = 2\nagent = { upstream = [{ name = \"a\", socket = \"/a\" }] }\n");
    assert!(matches!(doc.add_upstream("b", "/b"), Err(EditError::Unsupported { .. })));
    let (_, mut other) = open("version = 2\n[profile.p.ssh]\nkeys = \"all\"\n");
    other.set_profile("p", &setting("ssh.confirm=8h")).unwrap();
    assert_eq!(other.to_text(), "version = 2\n[profile.p.ssh]\nkeys = \"all\"\nconfirm = \"8h\"\n");
    drop(dir);
    let _ = doc.to_text();
}
