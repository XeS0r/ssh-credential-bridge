use std::time::Duration;

use credential_bridge_proto::ipc::git::Access;

use super::*;
use crate::paths::{PathVars, TargetOs};
use crate::pattern::GitTarget;
use crate::test_support::test_key;

fn paths() -> Paths {
    let vars = PathVars { home: Some("/home/u".into()), ..PathVars::default() };
    Paths::from_vars(&vars, TargetOs::Linux).unwrap()
}

/// The configuration example of `docs/architecture.md`, verbatim except that the
/// elided host keys are replaced by real (fake) keys.
fn design_example() -> String {
    let example = r#"# ~/.config/credential-bridge/config.toml
version = 2

[daemon]
socket         = "~/.local/state/credential-bridge/agent.sock"
forward_socket = "~/.local/state/credential-bridge/agent-forward.sock"

# ── Agent: which real agents sit behind the proxy ───────────────────
[agent]
add_to = "fido"                            # target for local ssh-add

[[agent.upstream]]
name   = "1password"
socket = "~/.1password/agent.sock"         # Linux; macOS: under ~/Library/Group Containers

[[agent.upstream]]
name   = "yubikey"                         # OpenPGP card via gpg-agent
socket = "gpgconf:agent-ssh-socket"

[[agent.upstream]]
name   = "fido"                            # ed25519-sk keys
socket = "~/.ssh/agent.sock"

# ── gpg: only needed if a profile allows gpg ─────────────────────────
[gpg]
socket = "gpgconf:agent-extra-socket"

# ── Vaults: only needed for KeePassXC through keepassxc-cli ──────────
[vault.keepassxc]
database = "~/Passwords/dev.kdbx"          # optional on Linux, required on macOS
key_file = "~/Passwords/dev.keyx"          # optional

# ── Sources: how tokens are made ─────────────────────────────────────
[source.github]
type = "github"
auth = "gh"

[source.github-ci]
type  = "github"
auth  = "pat"
token = "op://CI/github-readonly/credential"

[source.my-org]                            # written by "ctl source add github --auth app --create"
type            = "github"
auth            = "app"
app_id          = 123456
private_key     = "op://Dev/bridge-app/private-key"
max_permissions = { contents = "write", pull_requests = "write" }

[source.gitlab]
type  = "gitlab"
host  = "gitlab.example.com"
auth  = "token"
token = "bw://gitlab-team/token"

# ── Profiles: what a server may do ───────────────────────────────────
[profile.build]
ssh  = { keys = ["yubikey"] }              # only these upstreams are visible
gpg  = ["sign"]                            # sign yes, decrypt no
hops = { ssh = true, git = false, gpg = false }

[[profile.build.git]]
url         = "https://github.com/my-org/*"
source      = "my-org"
permissions = { contents = "write" }       # per = "repo" is the default

[[profile.build.git]]
url    = "https://gitlab.example.com/team/*"
source = "gitlab"

[profile.dev]
ssh     = { keys = "all", confirm = "8h" }  # approval dialog, valid 8 hours
signing = "ssh"                            # ctl sets up git signing via ssh

[[profile.dev.git]]
url    = "https://github.com/*"
source = "github"

# Hosts without a [server.*] entry get the built-in profile.unregistered:
# no keys (not even public ones), no tokens, no gpg. Nothing to write.
# To loosen it on purpose, for example:
# [profile.unregistered]
# ssh = { keys = ["fido"], confirm = "8h" }  # dialog, remembered 8h per host key

# ── Servers: written by ctl ──────────────────────────────────────────
[server.buildserver]
known_host = "buildserver"                 # its keys in known_hosts, followed
profile    = "build"

[server.devbox]
host_keys  = ["ssh-ed25519 AAAAC3Nz…"]     # pinned by "server add --pin"
profile    = "dev"
git_config = false                         # ctl does not touch git config there
"#;
    example.replacen("ssh-ed25519 AAAAC3Nz…", &test_key(2), 1)
}

fn parse(text: &str) -> Config {
    Config::parse(text, &paths()).unwrap_or_else(|e| panic!("{e}"))
}

/// The problems of an invalid configuration.
fn problems(text: &str) -> Vec<Problem> {
    match Config::parse(text, &paths()) {
        Err(ConfigError::Invalid { problems, .. }) => problems,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// Asserts a problem at `location` whose message contains `hint`.
fn assert_problem(problems: &[Problem], location: &str, hint: &str) {
    assert!(
        problems.iter().any(|p| p.location == location && p.message.contains(hint)),
        "no problem at {location} mentioning {hint:?} in {problems:#?}"
    );
}

fn key(seed: u8) -> ssh_key::PublicKey {
    ssh_key::PublicKey::from_openssh(&test_key(seed)).unwrap()
}

fn target(url: &str) -> GitTarget {
    GitTarget::parse_url(url).unwrap()
}

#[test]
fn design_example_parses_completely() {
    let config = parse(&design_example());
    assert!(config.validate().is_empty(), "{:?}", config.validate());

    let state = Path::new("/home/u/.local/state/credential-bridge");
    assert_eq!(config.daemon.socket, state.join("agent.sock"));
    assert_eq!(config.daemon.forward_socket, state.join("agent-forward.sock"));
    assert_eq!(config.daemon.control_socket, state.join("control.sock"));
    assert_eq!(config.daemon.audit_log, state.join("audit.log"));

    let agent = config.agent.as_ref().unwrap();
    assert_eq!(agent.add_to.as_deref(), Some("fido"));
    assert_eq!(
        agent.upstreams,
        vec![
            Upstream {
                name: "1password".into(),
                socket: SocketSpec::Path("/home/u/.1password/agent.sock".into())
            },
            Upstream { name: "yubikey".into(), socket: SocketSpec::Gpgconf("agent-ssh-socket".into()) },
            Upstream { name: "fido".into(), socket: SocketSpec::Path("/home/u/.ssh/agent.sock".into()) },
        ]
    );
    assert_eq!(config.gpg, Some(GpgConfig { socket: SocketSpec::Gpgconf("agent-extra-socket".into()) }));
    assert_eq!(
        config.vault.keepassxc,
        KeepassxcConfig {
            database: Some("/home/u/Passwords/dev.kdbx".into()),
            key_file: Some("/home/u/Passwords/dev.keyx".into()),
        }
    );

    assert_eq!(config.sources.len(), 4);
    assert_eq!(config.sources["github"].kind, SourceKind::GithubGh { host: "github.com".into() });
    assert_eq!(
        config.sources["github-ci"].kind,
        SourceKind::GithubPat {
            host: "github.com".into(),
            token: "op://CI/github-readonly/credential".parse().unwrap()
        }
    );
    assert_eq!(
        config.sources["my-org"].kind,
        SourceKind::GithubApp {
            host: "github.com".into(),
            api_url: "https://api.github.com".into(),
            app_id: 123456,
            private_key: "op://Dev/bridge-app/private-key".parse().unwrap(),
            max_permissions: [("contents".into(), Access::Write), ("pull_requests".into(), Access::Write)]
                .into(),
        }
    );
    assert_eq!(
        config.sources["gitlab"].kind,
        SourceKind::GitlabToken {
            host: "gitlab.example.com".into(),
            token: SecretRef::Bitwarden { item: "gitlab-team".into(), field: "token".into() }
        }
    );
    assert_eq!(config.sources["gitlab"].name, "gitlab");

    let build = &config.profiles["build"];
    assert_eq!(build.name, "build");
    assert_eq!(
        build.ssh,
        Some(SshPolicy { keys: KeySelection::Upstreams(vec!["yubikey".into()]), confirm: Confirm::Never })
    );
    assert_eq!(build.gpg, GpgPolicy { sign: true, decrypt: false });
    assert_eq!(build.hops, Hops { ssh: true, git: false, gpg: false });
    assert_eq!(build.signing, None);
    assert_eq!(build.git.len(), 2);
    assert_eq!(build.git[0].url.as_str(), "https://github.com/my-org/*");
    assert_eq!(build.git[0].source, "my-org");
    assert_eq!(build.git[0].permissions, [("contents".into(), Access::Write)].into());
    assert_eq!(build.git[0].per, TokenScope::Repo);
    assert_eq!(build.git[1].source, "gitlab");
    assert!(build.git[1].permissions.is_empty());
    assert!(build.shows_upstream("yubikey"));
    assert!(!build.shows_upstream("1password"));

    let dev = &config.profiles["dev"];
    assert_eq!(
        dev.ssh,
        Some(SshPolicy {
            keys: KeySelection::All,
            confirm: Confirm::Remember(Duration::from_secs(8 * 3600))
        })
    );
    assert_eq!(dev.signing, Some(Signing::Ssh));
    assert_eq!(dev.gpg, GpgPolicy::default());
    assert_eq!(dev.hops, Hops::default());
    assert!(dev.shows_upstream("fido"));

    // Nothing written: the built-in profile.unregistered.
    let unregistered = config.profile_for(None).unwrap();
    assert_eq!(*unregistered, Profile::unregistered());
    assert!(!config.profiles.contains_key("unregistered"));

    let buildserver = &config.servers["buildserver"];
    assert_eq!(buildserver.name, "buildserver");
    assert_eq!(buildserver.profile, "build");
    assert!(buildserver.git_config);
    assert_eq!(
        buildserver.keys,
        ServerKeys::KnownHost(KnownHost {
            name: "buildserver".into(),
            files: crate::known_hosts::default_files(Path::new("/home/u")),
        })
    );
    let devbox = &config.servers["devbox"];
    assert!(!devbox.git_config);
    assert_eq!(devbox.keys, ServerKeys::Pinned(vec![key(2)]));

    // The walk-through of "GitHub App tokens" in `docs/architecture.md`.
    let known_hosts = crate::known_hosts::KnownHosts::parse(&format!("buildserver {}\n", test_key(1)));
    let (map, _) = crate::host_keys::HostKeyMap::build_reporting(&config, |path| {
        Ok((path == Path::new("/home/u/.ssh/known_hosts")).then(|| known_hosts.clone()))
    });
    let crate::host_keys::Recognition::Server { name, .. } = map.recognise(&key(1)) else {
        panic!("not recognised")
    };
    let server = &config.servers[&name];
    assert_eq!(server.name, "buildserver");
    let profile = config.profile_for(Some(server)).unwrap();
    assert_eq!(profile.name, "build");
    let rule = profile.git_rule_for(&target("https://github.com/my-org/app.git")).unwrap();
    assert_eq!(rule.source, "my-org");
    assert_eq!(rule.url.owner_wildcard(), Some("my-org"));

    assert_eq!(
        config.git_hosts_for(buildserver),
        vec![("github.com".to_owned(), true), ("gitlab.example.com".to_owned(), true)]
    );
    assert_eq!(config.git_hosts_for(devbox), vec![("github.com".to_owned(), true)]);
}

#[test]
fn minimal_configuration_and_defaults() {
    let config = parse("version = 2\n");
    assert_eq!(config, Config::empty(&paths()));
    assert_eq!(config.agent, None);
    assert_eq!(config.profile_for(None), Some(&Profile::unregistered()));

    let config = parse(
        r#"
version = 2
[gpg]
[source.gh]
type = "github"
auth = "gh"
[profile.p]
gpg = ["sign", "decrypt"]
hops = { git = true }
[[profile.p.git]]
url = "https://github.com"
source = "gh"
"#,
    );
    assert_eq!(config.gpg, Some(GpgConfig { socket: SocketSpec::Gpgconf("agent-extra-socket".into()) }));
    let p = &config.profiles["p"];
    assert_eq!(p.ssh, None);
    assert!(!p.shows_upstream("anything"));
    assert_eq!(p.gpg, GpgPolicy { sign: true, decrypt: true });
    assert_eq!(p.hops, Hops { ssh: true, git: true, gpg: false });
    assert_eq!(p.git[0].per, TokenScope::Repo);
    assert_eq!(config.profile_for(None), Some(&Profile::unregistered()));
}

#[test]
fn unregistered_profile_is_built_in() {
    let builtin = Profile::unregistered();
    assert_eq!(builtin.name, "unregistered");
    assert_eq!(
        builtin.ssh,
        Some(SshPolicy { keys: KeySelection::Upstreams(Vec::new()), confirm: Confirm::Always })
    );
    assert!(!builtin.shows_upstream("fido"), "not even public keys");
    assert_eq!(builtin.hops, Hops { ssh: false, git: false, gpg: false });
    assert_eq!(builtin.gpg, GpgPolicy::default());
    assert_eq!(builtin.signing, None);
    assert!(builtin.git.is_empty());
    assert_eq!(Config::default().unregistered, builtin);
}

#[test]
fn unregistered_profile_overrides_single_fields() {
    let base = "version = 2\n[agent]\n[[agent.upstream]]\nname = \"fido\"\nsocket = \"/run/fido.sock\"\n";
    // The loosening example of docs/architecture.md and the README.
    let config =
        parse(&format!("{base}[profile.unregistered]\nssh = {{ keys = [\"fido\"], confirm = \"8h\" }}\n"));
    let unregistered = config.profile_for(None).unwrap();
    assert_eq!(
        unregistered.ssh,
        Some(SshPolicy {
            keys: KeySelection::Upstreams(vec!["fido".into()]),
            confirm: Confirm::Remember(Duration::from_secs(8 * 3600))
        })
    );
    assert_eq!(unregistered.hops, Hops::NONE, "hops stay off");
    assert!(config.profiles.is_empty());

    // confirm keeps "always" unless set; hops only where written.
    let config = parse(&format!(
        "{base}[profile.unregistered]\nssh = {{ keys = \"all\" }}\nhops = {{ ssh = true }}\n"
    ));
    let ssh = config.unregistered.ssh.as_ref().unwrap();
    assert_eq!((&ssh.keys, ssh.confirm), (&KeySelection::All, Confirm::Always));
    assert_eq!(config.unregistered.hops, Hops { ssh: true, git: false, gpg: false });

    // Only hops written: ssh stays built in.
    let config = parse(&format!("{base}[profile.unregistered]\nhops = {{ ssh = true }}\n"));
    assert_eq!(config.unregistered.ssh, Profile::unregistered().ssh);

    let config =
        parse(&format!("{base}[profile.unregistered]\nssh = {{ keys = [], confirm = \"never\" }}\n"));
    assert_eq!(config.unregistered.ssh.as_ref().unwrap().confirm, Confirm::Never);

    // Registered profiles: no confirm means no dialog; "always" and "never" are words.
    let config = parse(&format!(
        "{base}[profile.a]\nssh = {{ keys = \"all\" }}\n[profile.b]\nssh = {{ keys = \"all\", confirm = \"always\" }}\n"
    ));
    assert_eq!(config.profiles["a"].ssh.as_ref().unwrap().confirm, Confirm::Never);
    assert_eq!(config.profiles["b"].ssh.as_ref().unwrap().confirm, Confirm::Always);
}

#[test]
fn unregistered_profile_never_gets_tokens_or_gpg() {
    let p = problems(
        r#"version = 2
[gpg]
[source.gh]
type = "github"
auth = "gh"
[profile.unregistered]
ssh = { confirm = "8h" }
gpg = ["sign"]
signing = "ssh"
hops = { git = true }
[[profile.unregistered.git]]
url = "https://github.com/*"
source = "gh"
[profile.p]
[server.s]
host_keys = ["ssh-ed25519 AAAAC3Nz…"]
profile = "unregistered"
"#
        .replace("ssh-ed25519 AAAAC3Nz…", &test_key(1))
        .as_str(),
    );
    assert_problem(&p, "profile.unregistered.ssh.keys", "ssh needs keys");
    assert_problem(&p, "profile.unregistered.git", "never get tokens");
    assert_problem(&p, "profile.unregistered.gpg", "never get tokens, gpg");
    assert_problem(&p, "profile.unregistered.signing", "server add");
    assert_problem(&p, "profile.unregistered.hops", "only hops.ssh");
    assert_problem(&p, "server.s.profile", "a profile of its own");
    assert_eq!(p.len(), 6, "{p:#?}");
}

#[test]
fn profile_default_is_rejected() {
    let p = problems("version = 2\n[profile.default]\nssh = { keys = \"all\" }\n");
    assert_problem(&p, "profile.default", "profile.unregistered");
    assert_eq!(p.len(), 1, "{p:#?}");
}

#[test]
fn daemon_paths_are_expanded() {
    let config = parse(
        r#"
version = 2
[daemon]
socket = "/run/x/agent.sock"
forward_socket = "~/fwd.sock"
control_socket = "~/ctl.sock"
audit_log = "~/log/audit.log"
"#,
    );
    assert_eq!(config.daemon.socket, Path::new("/run/x/agent.sock"));
    assert_eq!(config.daemon.forward_socket, Path::new("/home/u/fwd.sock"));
    assert_eq!(config.daemon.control_socket, Path::new("/home/u/ctl.sock"));
    assert_eq!(config.daemon.audit_log, Path::new("/home/u/log/audit.log"));
}

#[test]
fn source_kinds_and_defaults() {
    let config = parse(
        r#"
version = 2
[source.ghe]
type = "github"
auth = "app"
host = "GHE.example.com"
app_id = 1
private_key = "keychain://bridge/key"
max_permissions = { contents = "read" }

[source.local]
type = "github"
auth = "app"
api_url = "https://ghe2.example.com:443/api/v3/"
app_id = 2
private_key = "pass://bridge/key"
max_permissions = { contents = "read" }

[source.forgejo]
type = "forgejo"
host = "codeberg.org"
token = "secret-service://service=codeberg"

[source.gitea]
type = "gitea"
auth = "token"
host = "gitea.example.com:3000"
token = "cmd:print-token"

[source.gcm]
type = "helper"
helper = "manager"
"#,
    );
    let SourceKind::GithubApp { host, api_url, .. } = &config.sources["ghe"].kind else { panic!() };
    assert_eq!(host, "ghe.example.com");
    assert_eq!(api_url, "https://ghe.example.com/api/v3");
    let SourceKind::GithubApp { api_url, .. } = &config.sources["local"].kind else { panic!() };
    assert_eq!(api_url, "https://ghe2.example.com:443/api/v3");
    assert!(
        matches!(&config.sources["forgejo"].kind, SourceKind::ForgejoToken { host, .. } if host == "codeberg.org")
    );
    assert!(
        matches!(&config.sources["gitea"].kind, SourceKind::ForgejoToken { host, .. } if host == "gitea.example.com:3000")
    );
    assert_eq!(config.sources["gcm"].kind, SourceKind::Helper { helper: "manager".into() });
    assert_eq!(config.sources["gcm"].kind.host(), None);
}

#[test]
fn cache_is_optional_for_sources_the_bridge_caches() {
    let config = parse(
        r#"
version = 2
[source.pat]
type = "github"
auth = "pat"
token = "op://Prod/github/credential"
cache = false
[source.app]
type = "github"
auth = "app"
app_id = 1
private_key = "op://Dev/app/key"
max_permissions = { contents = "read" }
cache = false
[source.gitlab]
type = "gitlab"
host = "gitlab.example.com"
token = "bw://gitlab/token"
cache = true
[source.gitea]
type = "gitea"
host = "gitea.example.com"
token = "cmd:print-token"
cache = false
[source.forgejo]
type = "forgejo"
host = "codeberg.org"
token = "pass://forgejo"
[source.gh]
type = "github"
auth = "gh"
"#,
    );
    let cache = |name: &str| config.sources[name].cache;
    assert!(!cache("pat") && !cache("app") && !cache("gitea"));
    assert!(cache("gitlab") && cache("forgejo") && cache("gh"), "default true");

    let p = problems(
        r#"
version = 2
[source.gh]
type = "github"
auth = "gh"
cache = false
[source.helper]
type = "helper"
helper = "manager"
cache = true
"#,
    );
    for name in ["gh", "helper"] {
        assert_problem(&p, &format!("source.{name}.cache"), "is not used with type = \"");
        assert_problem(
            &p,
            &format!("source.{name}.cache"),
            "the bridge caches no tokens of gh and helper sources",
        );
    }
}

#[test]
fn first_matching_rule_wins() {
    let config = parse(
        r#"
version = 2
[source.gh]
type = "github"
auth = "gh"
[source.ci]
type = "github"
auth = "pat"
token = "bw://ci/token"
[source.gcm]
type = "helper"
helper = "manager"
[profile.p]
[[profile.p.git]]
url = "https://github.com/special/repo"
source = "ci"
[[profile.p.git]]
url = "https://github.com/*"
source = "gh"
[[profile.p.git]]
url = "https://github.com/special/*"
source = "ci"
[[profile.p.git]]
url = "https://git.example.com"
source = "gcm"
"#,
    );
    let p = &config.profiles["p"];
    assert_eq!(p.git_rule_for(&target("https://github.com/special/repo.git")).unwrap().source, "ci");
    assert_eq!(p.git_rule_for(&target("https://github.com/special/other")).unwrap().source, "gh");
    assert_eq!(p.git_rule_for(&target("https://git.example.com/x/y")).unwrap().source, "gcm");
    assert!(p.git_rule_for(&target("https://gitlab.com/x/y")).is_none());
    assert!(p.git_rule_for(&target("https://github.com")).is_none(), "path patterns need a path");

    let server = Server {
        name: "s".into(),
        keys: ServerKeys::Pinned(vec![key(1)]),
        profile: "p".into(),
        git_config: true,
    };
    assert_eq!(
        config.git_hosts_for(&server),
        vec![("github.com".to_owned(), true), ("git.example.com".to_owned(), false)]
    );
    let unknown = Server { profile: "missing".into(), ..server };
    assert!(config.git_hosts_for(&unknown).is_empty());
}

#[test]
fn servers_follow_known_hosts_or_pin_keys() {
    let text = format!(
        "version = 2\n[profile.p]\n[server.a]\nhost_keys = [\"{} a@host\", \"{}\"]\nprofile = \"p\"\n\
         [server.b]\nknown_host = \"[b.example]:2222\"\nprofile = \"p\"\n\
         [server.c]\nknown_host = \"c\"\nknown_hosts_files = [\"~/.ssh/work\", \"/etc/ssh/work\"]\nprofile = \"p\"\n",
        test_key(1),
        test_key(2),
    );
    let config = parse(&text);
    let mut commented = key(1);
    commented.set_comment("a@host");
    assert_eq!(config.servers["a"].keys, ServerKeys::Pinned(vec![commented, key(2)]));
    let ServerKeys::KnownHost(b) = &config.servers["b"].keys else { panic!() };
    assert_eq!(b.name, "[b.example]:2222");
    assert_eq!(b.files, crate::known_hosts::default_files(Path::new("/home/u")));
    let ServerKeys::KnownHost(c) = &config.servers["c"].keys else { panic!() };
    assert_eq!(c.files, [PathBuf::from("/home/u/.ssh/work"), PathBuf::from("/etc/ssh/work")]);
    // Every file once, in configuration order.
    let files = config.known_hosts_files();
    assert_eq!(files.len(), 6, "{files:?}");
    assert_eq!(files[0], Path::new("/home/u/.ssh/known_hosts"));
    assert_eq!(files[4], Path::new("/home/u/.ssh/work"));
}

/// ssh lowercases the name before it looks it up or hashes it: a hand-written uppercase
/// `known_host` matches the hashed entry ssh wrote.
#[test]
fn known_host_is_lowercased() {
    let config = parse(
        "version = 2\n[profile.p]\n[server.a]\nknown_host = \"[Build.Example]:2222\"\nprofile = \"p\"\n",
    );
    let ServerKeys::KnownHost(known) = &config.servers["a"].keys else { panic!() };
    assert_eq!(known.name, "[build.example]:2222");
    // Written by OpenSSH 10.2's `ssh-keygen -H` for `[build.example]:2222`.
    let hashed = crate::known_hosts::KnownHosts::parse(&format!(
        "|1|TYmslNoqAWw3QHHnN7hzJXDI/Tc=|T7nh1FLc0sF7b77ZLOA2EXCDOsE= {}\n",
        test_key(1)
    ));
    let (map, _) = crate::host_keys::HostKeyMap::build_reporting(&config, |_| Ok(Some(hashed.clone())));
    assert!(
        matches!(map.recognise(&key(1)), crate::host_keys::Recognition::Server { name, .. } if name == "a")
    );
}

/// Two servers following the same name in the same files load, with a warning.
#[test]
fn the_same_known_host_twice_is_a_warning() {
    let config = parse(
        "version = 2\n[profile.p]\n[server.a]\nknown_host = \"box\"\nprofile = \"p\"\n\
         [server.b]\nknown_host = \"BOX\"\nprofile = \"p\"\n\
         [server.c]\nknown_host = \"box\"\nknown_hosts_files = [\"/etc/ssh/other\"]\nprofile = \"p\"\n\
         [server.d]\nknown_host = \"other\"\nprofile = \"p\"\n",
    );
    assert!(config.validate().is_empty());
    let warnings = config.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(warnings[0].location, "server.b.known_host");
    assert!(
        warnings[0].message.starts_with("server \"a\" follows \"box\" in the same known_hosts files"),
        "{}",
        warnings[0]
    );
    assert!(parse(&design_example()).warnings().is_empty());
}

#[test]
fn known_host_and_host_keys_exclude_each_other() {
    let p = problems(&format!(
        "version = 2\n[profile.p]\n[server.both]\nknown_host = \"both\"\nhost_keys = [\"{}\"]\nprofile = \"p\"\n\
         [server.none]\nprofile = \"p\"\n\
         [server.files]\nhost_keys = [\"{}\"]\nknown_hosts_files = [\"/k\"]\nprofile = \"p\"\n\
         [server.pattern]\nknown_host = \"*.example.com\"\nprofile = \"p\"\n\
         [server.port]\nknown_host = \"[x]\"\nknown_hosts_files = []\nprofile = \"p\"\n\
         [server.relative]\nknown_host = \"r\"\nknown_hosts_files = [\"known_hosts\"]\nprofile = \"p\"\n",
        test_key(1),
        test_key(2)
    ));
    assert_problem(&p, "server.both", "known_host and host_keys exclude each other");
    assert_problem(&p, "server.none", "needs known_host");
    assert_problem(&p, "server.files.known_hosts_files", "needs known_host");
    assert_problem(&p, "server.pattern.known_host", "not a pattern");
    assert_problem(&p, "server.port.known_host", "[host]:port");
    assert_problem(&p, "server.port.known_hosts_files", "no file listed");
    assert_problem(&p, "server.relative.known_hosts_files[0]", "must be absolute");
    // No follow-up problem about missing host keys.
    assert_eq!(p.len(), 7, "{p:#?}");
}

#[test]
fn legacy_configurations_are_rejected() {
    let legacy = r#"
backend = "gh"

[[remote]]
name = "buildserver"
allow = ["https://github.com/my-org/*"]
"#;
    let err = Config::parse(legacy, &paths()).unwrap_err();
    assert!(matches!(err, ConfigError::Legacy { .. }), "{err:?}");
    assert!(err.to_string().contains("0.1"));

    // A `remote` key wins even with a version.
    let mixed = "version = 2\n[[remote]]\nname = \"x\"\n";
    assert!(matches!(Config::parse(mixed, &paths()), Err(ConfigError::Legacy { .. })));

    // 0.1 without remotes, only top-level settings.
    assert!(matches!(Config::parse("timeout_secs = 5\n", &paths()), Err(ConfigError::Legacy { .. })));
}

#[test]
fn empty_documents_are_empty_configurations() {
    assert_eq!(parse(""), Config::empty(&paths()));
    assert_eq!(parse("# only a comment\n\n"), Config::empty(&paths()));
}

#[test]
fn version_is_checked() {
    for (text, expected) in [("version = 1\n", 1), ("version = 3\n", 3)] {
        match Config::parse(text, &paths()) {
            Err(ConfigError::Version { version, .. }) => assert_eq!(version, expected),
            other => panic!("{other:?}"),
        }
    }
    let err = Config::parse("version = \"2\"\n", &paths()).unwrap_err();
    assert!(matches!(&err, ConfigError::Syntax { message, .. } if message.contains("integer")), "{err:?}");
}

#[test]
fn syntax_and_schema_errors() {
    let err = Config::parse("version = 2\n[daemon\n", &paths()).unwrap_err();
    assert!(matches!(&err, ConfigError::Syntax { path, .. } if path == Path::new("<string>")));

    for (text, hint) in [
        ("version = 2\nunknown = 1\n", "unknown"),
        ("version = 2\n[daemon]\nsockets = \"/x\"\n", "sockets"),
        ("version = 2\n[profile.p]\nssh = { keys = \"all\", confrim = \"8h\" }\n", "confrim"),
        ("version = 2\n[profile.p]\nhops = { ssh = \"yes\" }\n", "ssh"),
        ("version = 2\n[server.s]\nprofile = 1\n", "profile"),
        (
            "version = 2\n[profile.p]\n[[profile.p.git]]\nurl = \"https://x\"\nsource = \"s\"\nper = \"org\"\n",
            "org",
        ),
        (
            "version = 2\n[source.s]\ntype = \"github\"\nauth = \"app\"\nmax_permissions = { contents = \"all\" }\n",
            "all",
        ),
    ] {
        match Config::parse(text, &paths()) {
            Err(ConfigError::Syntax { message, .. }) => {
                assert!(message.contains(hint), "{text:?}: {message}");
                assert!(message.contains("line"), "{text:?}: message without position: {message}");
            }
            other => panic!("{text:?}: expected Syntax, got {other:?}"),
        }
    }
}

#[test]
fn load_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("config.toml");
    assert_eq!(Config::load(&missing, &paths()).unwrap(), Config::empty(&paths()));

    std::fs::write(&missing, design_example()).unwrap();
    let config = Config::load(&missing, &paths()).unwrap();
    assert_eq!(config.servers.len(), 2);

    let legacy = dir.path().join("legacy.toml");
    std::fs::write(&legacy, "[[remote]]\nname = \"x\"\n").unwrap();
    match Config::load(&legacy, &paths()) {
        Err(ConfigError::Legacy { path }) => assert_eq!(path, legacy),
        other => panic!("{other:?}"),
    }

    let invalid = dir.path().join("invalid.toml");
    std::fs::write(&invalid, "version = 2\n[server.s]\nhost_keys = []\nprofile = \"p\"\n").unwrap();
    match Config::load(&invalid, &paths()) {
        Err(err @ ConfigError::Invalid { .. }) => {
            assert!(err.to_string().starts_with(&invalid.display().to_string()), "{err}");
        }
        other => panic!("{other:?}"),
    }

    // A directory cannot be read as a file.
    assert!(matches!(Config::load(dir.path(), &paths()), Err(ConfigError::Io { .. })));
}

#[test]
fn reference_problems() {
    let p = problems(
        r#"
version = 2
[agent]
add_to = "nope"
[[agent.upstream]]
name = "a"
socket = "/run/a.sock"
[[agent.upstream]]
name = "a"
socket = "/run/b.sock"
[profile.p]
ssh = { keys = ["a", "missing"] }
[[profile.p.git]]
url = "https://github.com/*"
source = "unknown"
[server.s]
host_keys = []
profile = "absent"
"#,
    );
    assert_problem(&p, "agent.add_to", "\"nope\"");
    assert_problem(&p, "agent.upstream[1].name", "defined twice");
    assert_problem(&p, "profile.p.ssh.keys", "\"missing\"");
    assert_problem(&p, "profile.p.git[0].source", "\"unknown\"");
    assert_problem(&p, "server.s.profile", "\"absent\"");
    assert_problem(&p, "server.s.host_keys", "no host key");
    assert_eq!(p.len(), 6, "{p:#?}");
}

#[test]
fn gpg_needs_a_gpg_table() {
    let p = problems("version = 2\n[profile.p]\ngpg = [\"decrypt\"]\n");
    assert_problem(&p, "profile.p.gpg", "no [gpg] table");
}

#[test]
fn ssh_keys_need_an_agent_block() {
    let p = problems("version = 2\n[profile.p]\nssh = { keys = [\"yubikey\"] }\n");
    assert_problem(&p, "profile.p.ssh.keys", "\"yubikey\"");
}

#[test]
fn value_problems() {
    let p = problems(
        r#"
version = 2
[[agent.upstream]]
name = "bad name"
socket = "relative.sock"
[[agent.upstream]]
name = "g"
socket = "gpgconf:homedir"
[source.tok]
type = "github"
auth = "pat"
token = "plaintext-token"
[source.weird]
type = "bitbucket"
[source.nohost]
type = "gitlab"
token = "bw://a/b"
[source.extra]
type = "github"
auth = "gh"
token = "bw://a/b"
[source.helperauth]
type = "helper"
auth = "token"
helper = "x"
[profile.p]
ssh = { keys = "some", confirm = "forever" }
gpg = ["sign", "encrypt"]
signing = "gpg"
[[profile.p.git]]
url = "github.com/x"
source = "tok"
[server.s]
host_keys = ["ssh-ed25519 AAAAC3Nz…"]
profile = "p"
"#,
    );
    assert_problem(&p, "agent.upstream[0].name", "invalid upstream name");
    assert_problem(&p, "agent.upstream[0].socket", "not absolute");
    assert_problem(&p, "agent.upstream[1].socket", "gpgconf:homedir");
    assert_problem(&p, "source.tok.token", "plaintext-token");
    assert_problem(&p, "source.weird.type", "unknown type");
    assert_problem(&p, "source.nohost.host", "needs host");
    assert_problem(&p, "source.extra.token", "not used");
    assert_problem(&p, "source.helperauth.auth", "no auth");
    assert_problem(&p, "profile.p.ssh.keys", "\"some\"");
    assert_problem(&p, "profile.p.ssh.confirm", "\"forever\"");
    assert_problem(&p, "profile.p.gpg", "\"encrypt\"");
    assert_problem(&p, "profile.p.signing", "\"gpg\"");
    assert_problem(&p, "profile.p.git[0].url", "missing scheme");
    assert_problem(&p, "server.s.host_keys[0]", "OpenSSH format");
    // Follow-up problems of the broken values are not repeated.
    assert!(!p.iter().any(|p| p.location == "server.s.host_keys"), "{p:#?}");
}

#[test]
fn broken_source_is_reported_once() {
    let p = problems(
        r#"
version = 2
[source.ci]
type = "github"
auth = "pat"
token = "nope"
[profile.p]
[[profile.p.git]]
url = "https://github.com/*"
source = "ci"
"#,
    );
    assert_eq!(p.len(), 1, "{p:#?}");
    assert_problem(&p, "source.ci.token", "invalid secret reference");
}

const RULE_SOURCES: &str = r#"
version = 2
[source.app]
type = "github"
auth = "app"
app_id = 1
private_key = "op://Dev/app/key"
max_permissions = { contents = "write", issues = "read" }
[source.pat]
type = "github"
auth = "pat"
token = "op://CI/pat/token"
[source.gl]
type = "gitlab"
host = "gitlab.example.com"
token = "bw://gl/token"
[source.gcm]
type = "helper"
helper = "manager"
[profile.p]
"#;

fn rule_problems(rule: &str) -> Vec<Problem> {
    problems(&format!("{RULE_SOURCES}[[profile.p.git]]\n{rule}\n"))
}

#[test]
fn rule_permissions_are_checked() {
    let ok = format!(
        "{RULE_SOURCES}[[profile.p.git]]\nurl = \"https://github.com/o/*\"\nsource = \"app\"\n\
         permissions = {{ contents = \"read\", issues = \"read\" }}\nper = \"owner\"\n"
    );
    let config = parse(&ok);
    assert_eq!(config.profiles["p"].git[0].per, TokenScope::Owner);

    let p = rule_problems(
        "url = \"https://github.com/o/*\"\nsource = \"app\"\npermissions = { contents = \"admin\", actions = \"read\" }",
    );
    assert_problem(&p, "profile.p.git[0].permissions", "contents = \"admin\" exceeds");
    assert_problem(&p, "profile.p.git[0].permissions", "actions = \"read\" exceeds");

    let p = rule_problems("url = \"https://github.com/o/*\"\nsource = \"app\"");
    assert_problem(&p, "profile.p.git[0].permissions", "needs permissions");

    let p = rule_problems(
        "url = \"https://github.com/o/*\"\nsource = \"pat\"\npermissions = { contents = \"read\" }",
    );
    assert_problem(&p, "profile.p.git[0].permissions", "only apply to GitHub App");
}

#[test]
fn rule_scope_is_checked() {
    for url in
        ["https://github.com/*", "https://github.com/o/r", "https://github.com/o/*/x", "https://github.com"]
    {
        let p = rule_problems(&format!(
            "url = \"{url}\"\nsource = \"app\"\npermissions = {{ contents = \"read\" }}\nper = \"owner\""
        ));
        assert_problem(&p, "profile.p.git[0].per", "<owner>/*");
    }
    let p = rule_problems("url = \"https://github.com/o/*\"\nsource = \"pat\"\nper = \"owner\"");
    assert_problem(&p, "profile.p.git[0].per", "only applies to GitHub App");
}

#[test]
fn rule_host_must_match_source() {
    let p = rule_problems("url = \"https://gitlab.com/team/*\"\nsource = \"gl\"");
    assert_problem(&p, "profile.p.git[0].url", "does not match host gitlab.example.com");
    let p = rule_problems("url = \"http://gitlab.example.com/team/*\"\nsource = \"gl\"");
    assert_problem(&p, "profile.p.git[0].url", "https://");
    let p = rule_problems("url = \"https://gitlab.example.com:8443/x\"\nsource = \"gl\"");
    assert_problem(&p, "profile.p.git[0].url", "does not match");

    // Helper sources serve any host and scheme.
    let config = parse(&format!(
        "{RULE_SOURCES}[[profile.p.git]]\nurl = \"http://anything.example.org/x\"\nsource = \"gcm\"\n"
    ));
    assert_eq!(config.profiles["p"].git.len(), 1);
}

#[test]
fn source_values_are_checked() {
    let p = problems(
        r#"
version = 2
[source.a]
type = "github"
auth = "app"
app_id = 0
api_url = "http://api.github.com"
private_key = "op://a/b/c"
max_permissions = {}
[source.b]
type = "github"
auth = "app"
[source.c]
type = "github"
[source.d]
type = "gitlab"
auth = "oauth"
host = "x"
token = "bw://a/b"
[source.e]
type = "helper"
helper = "  "
[source.f]
type = "forgejo"
host = "bad host!"
token = "bw://a/b"
"#,
    );
    assert_problem(&p, "source.a.app_id", "positive");
    assert_problem(&p, "source.a.api_url", "https://");
    assert_problem(&p, "source.a.max_permissions", "empty");
    assert_problem(&p, "source.b.app_id", "needs app_id");
    assert_problem(&p, "source.b.private_key", "needs private_key");
    assert_problem(&p, "source.b.max_permissions", "needs max_permissions");
    assert_problem(&p, "source.c.auth", "missing auth");
    assert_problem(&p, "source.d.auth", "\"oauth\"");
    assert_problem(&p, "source.e.helper", "empty");
    assert_problem(&p, "source.f.host", "invalid host");
}

#[test]
fn duplicate_host_keys_are_rejected() {
    let text = format!(
        "version = 2\n[profile.p]\n[server.a]\nhost_keys = [\"{k}\"]\nprofile = \"p\"\n\
         [server.b]\nhost_keys = [\"{k} other\"]\nprofile = \"p\"\n\
         [server.c]\nhost_keys = [\"{j}\", \"{j}\"]\nprofile = \"p\"\n",
        k = test_key(1),
        j = test_key(2)
    );
    let p = problems(&text);
    assert_problem(&p, "server.b.host_keys", "also pinned for server \"a\"");
    assert_problem(&p, "server.c.host_keys", "listed twice");
}

#[test]
fn socket_problems() {
    let long = format!("/{}", "s".repeat(120));
    let p = problems(&format!(
        "version = 2\n[daemon]\nsocket = \"{long}\"\nforward_socket = \"/run/x.sock\"\n\
         control_socket = \"/run/x.sock\"\naudit_log = \"audit.log\"\n[gpg]\nsocket = \"{long}\"\n"
    ));
    assert_problem(&p, "daemon.socket", "bytes long");
    assert_problem(&p, "daemon.control_socket", "daemon.forward_socket");
    assert_problem(&p, "daemon.audit_log", "not absolute");
    assert_problem(&p, "gpg.socket", "bytes long");
}

/// An upstream that is the proxy itself (directly or through a link) would make the
/// proxy ask itself for keys.
#[test]
fn upstream_must_not_be_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let own = dir.path().join("agent.sock");
    let link = dir.path().join("link.sock");
    std::fs::write(&own, "").unwrap();
    std::os::unix::fs::symlink(&own, &link).unwrap();
    let p = problems(&format!(
        "version = 2\n[daemon]\nsocket = \"{}\"\nforward_socket = \"/run/fwd.sock\"\n\
         [[agent.upstream]]\nname = \"a\"\nsocket = \"{}\"\n\
         [[agent.upstream]]\nname = \"b\"\nsocket = \"/run/fwd.sock\"\n\
         [[agent.upstream]]\nname = \"c\"\nsocket = \"/run/other.sock\"\n",
        own.display(),
        link.display()
    ));
    assert_problem(&p, "agent.upstream[0].socket", "is the proxy's own socket (daemon.socket = ");
    assert_problem(
        &p,
        "agent.upstream[1].socket",
        "/run/fwd.sock is the proxy's own socket (daemon.forward_socket = /run/fwd.sock)",
    );
    assert!(!p.iter().any(|problem| problem.location == "agent.upstream[2].socket"), "{p:#?}");

    // The default daemon sockets count too.
    let paths = paths();
    let p = problems(&format!(
        "version = 2\n[[agent.upstream]]\nname = \"a\"\nsocket = \"{}\"\n",
        paths.agent_socket.display()
    ));
    assert_problem(&p, "agent.upstream[0].socket", "daemon.socket");
}

#[test]
fn names_are_checked() {
    let text = format!(
        "version = 2\n[source.\"my org\"]\ntype = \"helper\"\nhelper = \"x\"\n[profile.\"a/b\"]\n\
         [server.\"x y\"]\nhost_keys = [\"{}\"]\nprofile = \"a/b\"\n",
        test_key(1)
    );
    let p = problems(&text);
    assert_problem(&p, "source.my org", "invalid source name");
    assert_problem(&p, "profile.a/b", "invalid profile name");
    assert_problem(&p, "server.x y", "invalid server name");
}

#[test]
fn validate_hand_built_configuration() {
    let mut config = parse(&design_example());
    assert!(config.validate().is_empty());

    config.servers.get_mut("devbox").unwrap().profile = "gone".into();
    config.profiles.get_mut("build").unwrap().ssh.as_mut().unwrap().confirm =
        Confirm::Remember(Duration::ZERO);
    config.unregistered.git = config.profiles["dev"].git.clone();
    config.gpg = None;
    config.daemon.socket = PathBuf::from("relative.sock");
    let p = config.validate();
    assert_problem(&p, "server.devbox.profile", "\"gone\"");
    assert_problem(&p, "profile.build.ssh.confirm", "between");
    assert_problem(&p, "profile.build.gpg", "no [gpg] table");
    assert_problem(&p, "profile.unregistered.git", "not allowed");
    assert_problem(&p, "daemon.socket", "not absolute");

    assert!(!Config::default().validate().is_empty(), "default daemon paths are empty");
    assert!(Config::empty(&paths()).validate().is_empty());
}

#[test]
fn invalid_error_lists_every_problem() {
    let err =
        Config::parse("version = 2\n[server.s]\nhost_keys = []\nprofile = \"p\"\n", &paths()).unwrap_err();
    let text = err.to_string();
    assert!(text.starts_with("<string>: 2 problem(s): "), "{text}");
    assert!(text.contains("server.s.profile: "), "{text}");
}

#[test]
fn api_url_must_use_port_443() {
    let p = problems(
        r#"
version = 2
[source.port]
type = "github"
auth = "app"
host = "ghe.example.com:8443"
app_id = 1
private_key = "op://a/b/c"
max_permissions = { contents = "read" }
[source.local]
type = "github"
auth = "app"
api_url = "http://127.0.0.1:8080"
app_id = 1
private_key = "op://a/b/c"
max_permissions = { contents = "read" }
"#,
    );
    assert_problem(&p, "source.port.api_url", "only allows connections to TCP port 443");
    assert_problem(&p, "source.local.api_url", "https://");
}

#[test]
fn keepassxc_vault_settings() {
    let base = "version = 2\n";
    assert_eq!(parse(base).vault, VaultConfig::default());
    let config = parse(&format!("{base}[vault.keepassxc]\ndatabase = \"/data/db.kdbx\"\n"));
    assert_eq!(config.vault.keepassxc.database.as_deref(), Some(Path::new("/data/db.kdbx")));
    assert_eq!(config.vault.keepassxc.key_file, None);

    let relative =
        problems(&format!("{base}[vault.keepassxc]\ndatabase = \"db.kdbx\"\nkey_file = \"keys/db.keyx\"\n"));
    assert_problem(&relative, "vault.keepassxc.database", "db.kdbx is not absolute");
    assert_problem(&relative, "vault.keepassxc.key_file", "keys/db.keyx is not absolute");

    let key_only = problems(&format!("{base}[vault.keepassxc]\nkey_file = \"~/db.keyx\"\n"));
    assert_problem(&key_only, "vault.keepassxc.key_file", "key_file needs database");

    let unknown = Config::parse(&format!("{base}[vault.keepassxc]\npath = \"/x\"\n"), &paths());
    assert!(matches!(unknown, Err(ConfigError::Syntax { .. })), "{unknown:?}");
}

/// On macOS a `keepassxc://` reference needs `[vault.keepassxc] database`; on Linux the
/// Secret Service of the running app is used without it. (Parsing applies the checks of
/// the build system, so this runs on Linux.)
#[cfg(not(target_os = "macos"))]
#[test]
fn keepassxc_database_is_required_on_macos() {
    let text = "version = 2

[source.forge]
type  = \"forgejo\"
host  = \"git.example.org\"
token = \"keepassxc://Dev/forge/password\"

[source.other]
type  = \"github\"
auth  = \"pat\"
token = \"op://CI/gh/credential\"
";
    let config = parse(text);
    assert!(validate::check_on(&config, &BTreeSet::new(), TargetOs::Linux).is_empty());
    let on_mac = validate::check_on(&config, &BTreeSet::new(), TargetOs::MacOs);
    assert_problem(&on_mac, "vault.keepassxc.database", "on macOS keepassxc:// references need");
    assert_problem(&on_mac, "vault.keepassxc.database", "used by source forge");
    assert!(!on_mac.iter().any(|p| p.message.contains("other")), "{on_mac:?}");

    let with_database = parse(&format!("{text}\n[vault.keepassxc]\ndatabase = \"~/db.kdbx\"\n"));
    assert!(validate::check_on(&with_database, &BTreeSet::new(), TargetOs::MacOs).is_empty());

    // Without a keepassxc:// reference nothing is required.
    let unused = parse("version = 2\n");
    assert!(validate::check_on(&unused, &BTreeSet::new(), TargetOs::MacOs).is_empty());
}

/// ctl reads `[daemon]` on its own where the file may not load; the rest of the file
/// may be invalid.
#[test]
fn daemon_settings_ignore_the_rest_of_the_file() {
    let default = DaemonConfig::from_paths(&paths());
    let custom = "version = 2\n[daemon]\nsocket = \"~/run/bridge.sock\"\ncontrol_socket = \"/run/c.sock\"\n\
                  forward_socket = \"~/run/f.sock\"\naudit_log = \"~/audit.log\"\n";
    let expected = DaemonConfig {
        socket: "/home/u/run/bridge.sock".into(),
        forward_socket: "/home/u/run/f.sock".into(),
        control_socket: "/run/c.sock".into(),
        audit_log: "/home/u/audit.log".into(),
    };
    assert_eq!(daemon_settings_in(custom, &paths()), expected);
    assert_eq!(Config::parse(custom, &paths()).unwrap().daemon, expected, "as Config::load reads it");
    let broken_elsewhere =
        format!("{custom}[profile.x]\nssh = {{ keys = 7 }}\n[source.y]\ntype = \"nope\"\n");
    assert!(Config::parse(&broken_elsewhere, &paths()).is_err());
    assert_eq!(daemon_settings_in(&broken_elsewhere, &paths()), expected);
    assert_eq!(daemon_settings_in("version = 2\n", &paths()), default);
    let forward = daemon_settings_in("version = 2\n[daemon]\nforward_socket = \"/x\"\n", &paths());
    assert_eq!(forward, DaemonConfig { forward_socket: "/x".into(), ..default.clone() });
    // Not TOML, or not a string, or relative: nothing can be trusted, the default is used.
    assert_eq!(daemon_settings_in("[daemon\nsocket = \"/x\"", &paths()), default);
    assert_eq!(daemon_settings_in("[daemon]\nsocket = 5\n", &paths()), default);
    assert_eq!(daemon_settings_in("[daemon]\nsocket = \"run/x\"\n", &paths()), default);
    assert_eq!(daemon_settings_in("daemon = 1\n", &paths()), default);

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    assert_eq!(daemon_settings(&file, &paths()), default, "missing file");
    std::fs::write(&file, &broken_elsewhere).unwrap();
    assert_eq!(daemon_settings(&file, &paths()), expected);
}
