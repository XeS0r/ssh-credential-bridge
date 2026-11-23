//! Service managers: systemd user units (Linux) and launchd agents (macOS).
//! Used by `credential-bridge-ctl daemon install|uninstall|start|stop|status`.

use std::fmt::Debug;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The service to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// Unit / job name: `credential-bridge` (systemd: `credential-bridge.service`;
    /// launchd label: `io.github.xes0r.credential-bridge`).
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Absolute path of `credential-bridged`.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<String>,
    /// Extra environment, e.g. `SSH_ASKPASS`.
    pub env: Vec<(String, String)>,
    /// Where stdout/stderr go (launchd); systemd uses the journal.
    pub log_file: Option<PathBuf>,
}

/// State of the installed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// No unit / plist is installed.
    NotInstalled,
    /// Installed, not running.
    Stopped,
    /// Running.
    Running {
        /// Main process id, if reported.
        pid: Option<u32>,
    },
    /// Installed and failed; the manager's explanation.
    Failed(String),
}

/// Errors of service operations.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Writing or removing the unit file failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// `systemctl` / `launchctl` failed.
    #[error("{command} failed: {message}")]
    Manager {
        /// The command line.
        command: String,
        /// Its stderr or exit status.
        message: String,
    },
}

/// One service manager.
pub trait ServiceManager: Debug {
    /// `systemd` or `launchd`.
    fn name(&self) -> &'static str;
    /// Where the unit file / plist for `spec` lives.
    fn unit_path(&self, spec: &ServiceSpec) -> PathBuf;
    /// The unit file / plist text (pure).
    fn render(&self, spec: &ServiceSpec) -> String;
    /// Writes the unit, reloads the manager and enables + starts the service.
    /// Re-installing replaces the unit and restarts.
    fn install(&self, spec: &ServiceSpec) -> Result<(), ServiceError>;
    /// Stops, disables and removes the unit. Not installed is not an error.
    fn uninstall(&self, spec: &ServiceSpec) -> Result<(), ServiceError>;
    /// Starts the service.
    fn start(&self, spec: &ServiceSpec) -> Result<(), ServiceError>;
    /// Stops the service.
    fn stop(&self, spec: &ServiceSpec) -> Result<(), ServiceError>;
    /// Reports the state.
    fn status(&self, spec: &ServiceSpec) -> Result<ServiceState, ServiceError>;
}

/// systemd user units under `unit_dir` (`$XDG_CONFIG_HOME/systemd/user`), driven with
/// `systemctl --user`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUser {
    /// Directory for the unit file.
    pub unit_dir: PathBuf,
}

impl ServiceManager for SystemdUser {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn unit_path(&self, spec: &ServiceSpec) -> PathBuf {
        self.unit_dir.join(format!("{}.service", spec.name))
    }

    fn render(&self, spec: &ServiceSpec) -> String {
        let mut unit = String::new();
        let exec: Vec<String> = std::iter::once(spec.program.to_string_lossy().into_owned())
            .chain(spec.args.iter().cloned())
            .collect();
        let _ = writeln!(unit, "[Unit]");
        let _ = writeln!(unit, "Description={}", systemd_line(&spec.description));
        let _ = writeln!(unit);
        let _ = writeln!(unit, "[Service]");
        let _ = writeln!(unit, "Type=exec");
        let _ = writeln!(
            unit,
            "ExecStart={}",
            exec.iter().map(|a| systemd_quote(a)).collect::<Vec<_>>().join(" ")
        );
        for (key, value) in &spec.env {
            let _ = writeln!(unit, "Environment={}", systemd_env_quote(&format!("{key}={value}")));
        }
        let _ = writeln!(unit, "Restart=on-failure");
        let _ = writeln!(unit, "RestartSec=2s");
        let _ = writeln!(unit, "LimitCORE=0");
        let _ = writeln!(unit);
        let _ = writeln!(unit, "[Install]");
        let _ = writeln!(unit, "WantedBy=default.target");
        unit
    }

    fn install(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.install_with(spec, &mut run)
    }

    fn uninstall(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.uninstall_with(spec, &mut run)
    }

    fn start(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        run(&systemctl(&["start", &systemd_unit(spec)])).map(drop)
    }

    fn stop(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        run(&systemctl(&["stop", &systemd_unit(spec)])).map(drop)
    }

    fn status(&self, spec: &ServiceSpec) -> Result<ServiceState, ServiceError> {
        self.status_with(spec, &mut run)
    }
}

impl SystemdUser {
    fn install_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        write_file(&self.unit_path(spec), &self.render(spec))?;
        let unit = systemd_unit(spec);
        run(&systemctl(&["daemon-reload"]))?;
        run(&systemctl(&["enable", &unit]))?;
        run(&systemctl(&["restart", &unit]))?;
        Ok(())
    }

    fn uninstall_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        let path = self.unit_path(spec);
        if !path.exists() {
            return Ok(());
        }
        run(&systemctl(&["disable", "--now", &systemd_unit(spec)]))?;
        remove_file(&path)?;
        run(&systemctl(&["daemon-reload"]))?;
        Ok(())
    }

    fn status_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<ServiceState, ServiceError> {
        if !self.unit_path(spec).exists() {
            return Ok(ServiceState::NotInstalled);
        }
        let unit = systemd_unit(spec);
        let show = run(&systemctl(&["show", &unit, "--property=ActiveState,SubState,MainPID,Result"]))?;
        Ok(parse_systemctl_show(&show))
    }
}

fn systemd_unit(spec: &ServiceSpec) -> String {
    format!("{}.service", spec.name)
}

fn systemctl(args: &[&str]) -> Vec<String> {
    ["systemctl", "--user"].iter().chain(args).map(|s| (*s).to_owned()).collect()
}

/// Maps `systemctl show` properties to a state.
fn parse_systemctl_show(text: &str) -> ServiceState {
    let property = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
            .unwrap_or("")
    };
    let pid = property("MainPID").parse::<u32>().ok().filter(|&pid| pid > 0);
    match property("ActiveState") {
        "active" | "activating" | "reloading" | "deactivating" | "refreshing" => {
            ServiceState::Running { pid }
        }
        "failed" => ServiceState::Failed(format!("{} ({})", property("Result"), property("SubState"))),
        _ => ServiceState::Stopped,
    }
}

/// One value of a unit file line: no line breaks, `%` specifiers escaped.
fn systemd_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ").replace('%', "%%")
}

/// A double-quoted word for `ExecStart=`, with C escapes, `%%` for specifiers and `$$`
/// against variable expansion.
fn systemd_quote(word: &str) -> String {
    systemd_quoted(word, true)
}

/// A double-quoted assignment for `Environment=`: C escapes and `%%` for specifiers like
/// [`systemd_quote`], but `$` stays as it is, because systemd expands no variables in
/// `Environment=` (a `$$` would reach the program as two dollar signs).
fn systemd_env_quote(assignment: &str) -> String {
    systemd_quoted(assignment, false)
}

/// The quoting of [`systemd_quote`] and [`systemd_env_quote`]; `dollars` doubles `$`.
fn systemd_quoted(word: &str, dollars: bool) -> String {
    let mut out = String::from("\"");
    for c in word.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '%' => out.push_str("%%"),
            '$' if dollars => out.push_str("$$"),
            c if c.is_ascii_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// launchd agents under `agents_dir` (`~/Library/LaunchAgents`), driven with
/// `launchctl bootstrap/bootout gui/<uid>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launchd {
    /// Directory for the plist.
    pub agents_dir: PathBuf,
}

/// Prefix of launchd labels.
pub const LAUNCHD_LABEL_PREFIX: &str = "io.github.xes0r.";

impl ServiceManager for Launchd {
    fn name(&self) -> &'static str {
        "launchd"
    }

    fn unit_path(&self, spec: &ServiceSpec) -> PathBuf {
        self.agents_dir.join(format!("{LAUNCHD_LABEL_PREFIX}{}.plist", spec.name))
    }

    fn render(&self, spec: &ServiceSpec) -> String {
        let mut plist = String::from(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n<dict>\n",
        ));
        let _ =
            writeln!(plist, "  <key>Label</key>\n  <string>{}</string>", xml_escape(&launchd_label(spec)));
        let program = spec.program.to_string_lossy();
        let _ = writeln!(plist, "  <key>ProgramArguments</key>\n  <array>");
        for arg in std::iter::once(program.as_ref()).chain(spec.args.iter().map(String::as_str)) {
            let _ = writeln!(plist, "    <string>{}</string>", xml_escape(arg));
        }
        let _ = writeln!(plist, "  </array>");
        if !spec.env.is_empty() {
            let _ = writeln!(plist, "  <key>EnvironmentVariables</key>\n  <dict>");
            for (key, value) in &spec.env {
                let _ = writeln!(
                    plist,
                    "    <key>{}</key>\n    <string>{}</string>",
                    xml_escape(key),
                    xml_escape(value)
                );
            }
            let _ = writeln!(plist, "  </dict>");
        }
        let _ = writeln!(plist, "  <key>RunAtLoad</key>\n  <true/>");
        let _ = writeln!(
            plist,
            "  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>"
        );
        let _ = writeln!(plist, "  <key>ThrottleInterval</key>\n  <integer>5</integer>");
        let _ = writeln!(
            plist,
            "  <key>SoftResourceLimits</key>\n  <dict>\n    <key>Core</key>\n    <integer>0</integer>\n  </dict>"
        );
        let _ = writeln!(
            plist,
            "  <key>HardResourceLimits</key>\n  <dict>\n    <key>Core</key>\n    <integer>0</integer>\n  </dict>"
        );
        if let Some(log) = &spec.log_file {
            let log = xml_escape(&log.to_string_lossy());
            let _ = writeln!(plist, "  <key>StandardOutPath</key>\n  <string>{log}</string>");
            let _ = writeln!(plist, "  <key>StandardErrorPath</key>\n  <string>{log}</string>");
        }
        plist.push_str("</dict>\n</plist>\n");
        plist
    }

    fn install(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.install_with(spec, &mut run)
    }

    fn uninstall(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.uninstall_with(spec, &mut run)
    }

    fn start(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.start_with(spec, &mut run)
    }

    /// Unloads the job (`bootout`), because launchd would restart a killed job; the
    /// plist stays, so it loads again at the next login or [`ServiceManager::start`].
    fn stop(&self, spec: &ServiceSpec) -> Result<(), ServiceError> {
        self.stop_with(spec, &mut run)
    }

    fn status(&self, spec: &ServiceSpec) -> Result<ServiceState, ServiceError> {
        self.status_with(spec, &mut run)
    }
}

impl Launchd {
    fn install_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        if let Some(parent) = self.unit_path(spec).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|source| ServiceError::Io { path: parent.to_owned(), source })?;
        }
        if let Some(log) = spec.log_file.as_deref().and_then(Path::parent) {
            std::fs::create_dir_all(log)
                .map_err(|source| ServiceError::Io { path: log.to_owned(), source })?;
        }
        // A loaded job keeps its old definition until it is booted out.
        self.stop_with(spec, run)?;
        write_file(&self.unit_path(spec), &self.render(spec))?;
        self.start_with(spec, run)
    }

    fn uninstall_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        let path = self.unit_path(spec);
        self.stop_with(spec, run)?;
        if path.exists() {
            remove_file(&path)?;
        }
        Ok(())
    }

    fn start_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        let target = launchd_target(spec);
        if !is_loaded(&target, run) {
            let plist = self.unit_path(spec).to_string_lossy().into_owned();
            run(&strings(&["launchctl", "enable", &target]))?;
            run(&strings(&["launchctl", "bootstrap", &launchd_domain(), &plist]))?;
        }
        run(&strings(&["launchctl", "kickstart", &target])).map(drop)
    }

    fn stop_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<(), ServiceError> {
        let target = launchd_target(spec);
        if is_loaded(&target, run) {
            run(&strings(&["launchctl", "bootout", &target]))?;
        }
        Ok(())
    }

    fn status_with(&self, spec: &ServiceSpec, run: &mut Runner<'_>) -> Result<ServiceState, ServiceError> {
        if !self.unit_path(spec).exists() {
            return Ok(ServiceState::NotInstalled);
        }
        match run(&strings(&["launchctl", "print", &launchd_target(spec)])) {
            Ok(text) => Ok(parse_launchctl_print(&text)),
            // Not loaded.
            Err(ServiceError::Manager { .. }) => Ok(ServiceState::Stopped),
            Err(e) => Err(e),
        }
    }
}

fn is_loaded(target: &str, run: &mut Runner<'_>) -> bool {
    run(&strings(&["launchctl", "print", target])).is_ok()
}

fn launchd_label(spec: &ServiceSpec) -> String {
    format!("{LAUNCHD_LABEL_PREFIX}{}", spec.name)
}

fn launchd_domain() -> String {
    format!("gui/{}", crate::peer::current_uid())
}

fn launchd_target(spec: &ServiceSpec) -> String {
    format!("{}/{}", launchd_domain(), launchd_label(spec))
}

/// Maps `launchctl print` output to a state.
fn parse_launchctl_print(text: &str) -> ServiceState {
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.trim().split_once(" = ")?;
            (key == name).then(|| value.trim())
        })
    };
    if field("state") == Some("running") {
        let pid = field("pid").and_then(|p| p.parse::<u32>().ok()).filter(|&p| p > 0);
        return ServiceState::Running { pid };
    }
    match field("last exit code") {
        Some(code) if code != "0" && !code.starts_with("(never") => {
            ServiceState::Failed(format!("last exit code {code}"))
        }
        _ => ServiceState::Stopped,
    }
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Not representable in XML 1.0.
            c if c.is_control() && !matches!(c, '\n' | '\t') => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// Runs a command line and returns its stdout; a failure is [`ServiceError::Manager`].
type Runner<'a> = dyn FnMut(&[String]) -> Result<String, ServiceError> + 'a;

fn run(argv: &[String]) -> Result<String, ServiceError> {
    let command = argv.join(" ");
    let (program, args) = argv.split_first().expect("non-empty command line");
    let output = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| ServiceError::Manager { command: command.clone(), message: e.to_string() })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let message = if stderr.is_empty() { output.status.to_string() } else { stderr };
        return Err(ServiceError::Manager { command, message });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}

/// Writes `text` to `path` atomically (temporary file + rename), creating the directory.
fn write_file(path: &Path, text: &str) -> Result<(), ServiceError> {
    let io = |source| ServiceError::Io { path: path.to_owned(), source };
    let dir = path.parent().ok_or_else(|| io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
    std::fs::create_dir_all(dir).map_err(io)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        std::fs::remove_file(&tmp).ok();
        io(e)
    })
}

fn remove_file(path: &Path) -> Result<(), ServiceError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(ServiceError::Io { path: path.to_owned(), source: e })
        }
        _ => Ok(()),
    }
}

/// The manager for this system: [`Launchd`] on macOS, [`SystemdUser`] elsewhere.
/// `home` and `xdg_config_home` locate the unit directory.
pub fn system_service_manager(home: &Path, xdg_config_home: Option<&Path>) -> Box<dyn ServiceManager> {
    if cfg!(target_os = "macos") {
        Box::new(Launchd { agents_dir: home.join("Library/LaunchAgents") })
    } else {
        let config = xdg_config_home.map_or_else(|| home.join(".config"), Path::to_path_buf);
        Box::new(SystemdUser { unit_dir: config.join("systemd/user") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            name: "credential-bridge".to_owned(),
            description: "credential-bridge agent proxy".to_owned(),
            program: PathBuf::from("/opt/cb dir/credential-bridged"),
            args: vec!["run".to_owned(), "--config=%h/$X \"q\"".to_owned()],
            env: vec![("SSH_ASKPASS".to_owned(), "/usr/bin/ssh-askpass".to_owned())],
            log_file: Some(PathBuf::from("/Users/u/Library/Logs/credential-bridge/daemon.log")),
        }
    }

    /// A fake `systemctl`/`launchctl` that records command lines and answers from a
    /// closure.
    struct Fake<F: FnMut(&[String]) -> Result<String, ServiceError>> {
        calls: Vec<String>,
        answer: F,
    }

    impl<F: FnMut(&[String]) -> Result<String, ServiceError>> Fake<F> {
        fn new(answer: F) -> Self {
            Fake { calls: Vec::new(), answer }
        }

        fn runner(&mut self) -> impl FnMut(&[String]) -> Result<String, ServiceError> + '_ {
            |argv: &[String]| {
                self.calls.push(argv.join(" "));
                (self.answer)(argv)
            }
        }
    }

    fn not_loaded() -> ServiceError {
        ServiceError::Manager {
            command: "launchctl print".to_owned(),
            message: "Could not find service".to_owned(),
        }
    }

    #[test]
    fn renders_a_systemd_unit() {
        let unit = SystemdUser { unit_dir: PathBuf::from("/x") }.render(&spec());
        assert_eq!(
            unit,
            "[Unit]\n\
             Description=credential-bridge agent proxy\n\
             \n\
             [Service]\n\
             Type=exec\n\
             ExecStart=\"/opt/cb dir/credential-bridged\" \"run\" \"--config=%%h/$$X \\\"q\\\"\"\n\
             Environment=\"SSH_ASKPASS=/usr/bin/ssh-askpass\"\n\
             Restart=on-failure\n\
             RestartSec=2s\n\
             LimitCORE=0\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        );
    }

    #[test]
    fn systemd_quoting() {
        assert_eq!(systemd_quote("a\\b\nc"), "\"a\\\\b\\nc\"");
        assert_eq!(systemd_quote("$HOME 100%"), "\"$$HOME 100%%\"");
        assert_eq!(systemd_quote("a\x01b\u{85}c"), "\"a\\x01b\\u0085c\"");
        assert_eq!(systemd_line("x\ny 100%"), "x y 100%%");
    }

    /// `Environment=` expands `%` specifiers but no variables: `$` stays single.
    #[test]
    fn systemd_environment_quoting() {
        assert_eq!(systemd_env_quote("PS=$1 100%"), "\"PS=$1 100%%\"");
        assert_eq!(systemd_env_quote("A=\"q\" \\ x"), "\"A=\\\"q\\\" \\\\ x\"");
        assert_eq!(systemd_env_quote("A=1\n2\t3\x7f\u{9b}"), "\"A=1\\n2\\t3\\x7f\\u009b\"");
        let unit = SystemdUser { unit_dir: PathBuf::from("/x") }.render(&ServiceSpec {
            env: vec![("SSH_ASKPASS".to_owned(), "/opt/$pass%h/askpass".to_owned())],
            ..spec()
        });
        assert!(unit.contains("Environment=\"SSH_ASKPASS=/opt/$pass%%h/askpass\"\n"), "{unit}");
    }

    #[test]
    fn systemd_install_status_uninstall() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SystemdUser { unit_dir: dir.path().join("systemd/user") };
        let spec = spec();
        let mut fake = Fake::new(|argv: &[String]| {
            Ok(if argv.get(2).is_some_and(|a| a == "show") {
                "ActiveState=active\nSubState=running\nMainPID=4242\nResult=success\n".to_owned()
            } else {
                String::new()
            })
        });

        assert_eq!(manager.status_with(&spec, &mut fake.runner()).unwrap(), ServiceState::NotInstalled);
        manager.install_with(&spec, &mut fake.runner()).unwrap();
        let path = manager.unit_path(&spec);
        assert_eq!(path, dir.path().join("systemd/user/credential-bridge.service"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), manager.render(&spec));
        assert_eq!(
            manager.status_with(&spec, &mut fake.runner()).unwrap(),
            ServiceState::Running { pid: Some(4242) }
        );
        manager.uninstall_with(&spec, &mut fake.runner()).unwrap();
        assert!(!path.exists());
        // Not installed is not an error.
        manager.uninstall_with(&spec, &mut fake.runner()).unwrap();

        assert_eq!(
            fake.calls,
            [
                "systemctl --user daemon-reload",
                "systemctl --user enable credential-bridge.service",
                "systemctl --user restart credential-bridge.service",
                "systemctl --user show credential-bridge.service --property=ActiveState,SubState,MainPID,Result",
                "systemctl --user disable --now credential-bridge.service",
                "systemctl --user daemon-reload",
            ]
        );
    }

    #[test]
    fn parses_systemctl_show() {
        assert_eq!(parse_systemctl_show("ActiveState=inactive\nMainPID=0\n"), ServiceState::Stopped);
        assert_eq!(
            parse_systemctl_show("ActiveState=activating\nMainPID=0\n"),
            ServiceState::Running { pid: None }
        );
        assert_eq!(
            parse_systemctl_show("ActiveState=failed\nSubState=failed\nResult=exit-code\nMainPID=0\n"),
            ServiceState::Failed("exit-code (failed)".to_owned())
        );
    }

    #[test]
    fn renders_a_launchd_plist() {
        let plist = Launchd { agents_dir: PathBuf::from("/x") }.render(&spec());
        assert!(plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
        assert!(plist.contains("<key>Label</key>\n  <string>io.github.xes0r.credential-bridge</string>"));
        assert!(plist.contains(
            "<array>\n    <string>/opt/cb dir/credential-bridged</string>\n    <string>run</string>\n    \
             <string>--config=%h/$X &quot;q&quot;</string>\n  </array>"
        ));
        assert!(plist.contains("<key>SSH_ASKPASS</key>\n    <string>/usr/bin/ssh-askpass</string>"));
        assert!(plist.contains("<key>StandardErrorPath</key>\n  <string>/Users/u/Library/Logs/credential-bridge/daemon.log</string>"));
        assert!(plist.contains("<key>Core</key>\n    <integer>0</integer>"));
        assert!(plist.ends_with("</dict>\n</plist>\n"));
        assert_eq!(xml_escape("a<b>&'\u{1}"), "a&lt;b&gt;&amp;&apos;\u{fffd}");
    }

    #[test]
    fn launchd_install_stop_status() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Launchd { agents_dir: dir.path().join("LaunchAgents") };
        let spec = ServiceSpec { log_file: Some(dir.path().join("Logs/cb/daemon.log")), ..spec() };
        let target = launchd_target(&spec);
        let plist = manager.unit_path(&spec);
        let mut loaded = false;
        let mut fake = Fake::new(|argv: &[String]| match argv[1].as_str() {
            "print" if loaded => {
                Ok("\tstate = running\n\tpid = 99\n\tlast exit code = (never exited)\n".to_owned())
            }
            "print" => Err(not_loaded()),
            "bootstrap" => {
                loaded = true;
                Ok(String::new())
            }
            "bootout" => {
                loaded = false;
                Ok(String::new())
            }
            _ => Ok(String::new()),
        });

        assert_eq!(manager.status_with(&spec, &mut fake.runner()).unwrap(), ServiceState::NotInstalled);
        manager.install_with(&spec, &mut fake.runner()).unwrap();
        assert!(plist.exists());
        assert!(dir.path().join("Logs/cb").is_dir());
        assert_eq!(
            manager.status_with(&spec, &mut fake.runner()).unwrap(),
            ServiceState::Running { pid: Some(99) }
        );
        manager.stop_with(&spec, &mut fake.runner()).unwrap();
        assert_eq!(manager.status_with(&spec, &mut fake.runner()).unwrap(), ServiceState::Stopped);
        manager.uninstall_with(&spec, &mut fake.runner()).unwrap();
        assert!(!plist.exists());

        let domain = launchd_domain();
        let expected: Vec<String> = vec![
            format!("launchctl print {target}"),
            format!("launchctl print {target}"),
            format!("launchctl enable {target}"),
            format!("launchctl bootstrap {domain} {}", plist.display()),
            format!("launchctl kickstart {target}"),
            format!("launchctl print {target}"),
            format!("launchctl print {target}"),
            format!("launchctl bootout {target}"),
            format!("launchctl print {target}"),
            format!("launchctl print {target}"),
        ];
        assert_eq!(fake.calls, expected);
    }

    #[test]
    fn parses_launchctl_print() {
        assert_eq!(
            parse_launchctl_print("gui/501/x = {\n\tstate = running\n\tpid = 123\n}"),
            ServiceState::Running { pid: Some(123) }
        );
        assert_eq!(
            parse_launchctl_print("\tstate = not running\n\tlast exit code = 0\n"),
            ServiceState::Stopped
        );
        assert_eq!(
            parse_launchctl_print("\tstate = not running\n\tlast exit code = 78: EX_CONFIG\n"),
            ServiceState::Failed("last exit code 78: EX_CONFIG".to_owned())
        );
    }

    #[test]
    fn system_manager_paths() {
        let home = Path::new("/home/u");
        let manager = system_service_manager(home, Some(Path::new("/cfg")));
        let path = manager.unit_path(&spec());
        if cfg!(target_os = "macos") {
            assert_eq!(
                path,
                Path::new("/home/u/Library/LaunchAgents/io.github.xes0r.credential-bridge.plist")
            );
        } else {
            assert_eq!(path, Path::new("/cfg/systemd/user/credential-bridge.service"));
            let default = system_service_manager(home, None).unit_path(&spec());
            assert_eq!(default, Path::new("/home/u/.config/systemd/user/credential-bridge.service"));
        }
    }
}
