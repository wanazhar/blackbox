//! Project paths and runtime configuration for blackbox.

use std::path::{Path, PathBuf};

/// Resolved filesystem layout for a blackbox store.
#[derive(Debug, Clone)]
pub struct BlackboxPaths {
    /// Root directory (usually `<project>/.blackbox`).
    pub root: PathBuf,
    /// SQLite database path.
    pub db_path: PathBuf,
    /// Content-addressed blob directory.
    pub blob_dir: PathBuf,
}

/// Check if a file is readable (has read permission).
fn is_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o444 != 0)
        .unwrap_or(false)
}

impl BlackboxPaths {
    /// Resolve store paths.
    ///
    /// Priority:
    /// 1. Explicit `db_override` (CLI `--store`)
    /// 2. `BLACKBOX_DB` environment variable
    /// 3. Legacy `./blackbox.db` if it already exists (migration)
    /// 4. `<project>/.blackbox/blackbox.db` (default)
    ///
    /// `project` defaults to the current working directory.
    pub fn resolve(project: Option<&Path>, db_override: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(db) = db_override {
            return Ok(Self::from_db_path(db.to_path_buf()));
        }

        if let Ok(env_db) = std::env::var("BLACKBOX_DB") {
            // M-11: An empty string is treated as "not set" — the variable is
            // ignored and fallback resolution (legacy path → default) proceeds.
            if !env_db.is_empty() {
                let env_path = PathBuf::from(&env_db);
                if env_path.is_dir() {
                    anyhow::bail!("BLACKBOX_DB points to a directory, not a file: {}", env_db);
                }
                if env_path.exists() && !is_readable(&env_path) {
                    anyhow::bail!("BLACKBOX_DB is not readable: {}", env_db);
                }
                return Ok(Self::from_db_path(env_path));
            }
        }

        let project = match project {
            Some(p) => {
                if p.exists() {
                    std::fs::canonicalize(p)?
                } else {
                    p.to_path_buf()
                }
            }
            None => std::env::current_dir()?,
        };

        // Legacy: keep using cwd blackbox.db if present so existing traces survive.
        //
        // M-12: This check has an inherent TOCTOU race (the file could appear
        // or disappear between `exists()` and `open()`), but the window is
        // negligible in practice and the worst case (a brief "not found" error
        // at open time) is acceptable for this migration path.
        let legacy = project.join("blackbox.db");
        if legacy.exists() {
            return Ok(Self::from_db_path(legacy));
        }

        let root = project.join(".blackbox");
        let db_path = root.join("blackbox.db");
        let blob_dir = root.join("blobs");
        Ok(Self {
            root,
            db_path,
            blob_dir,
        })
    }

    /// Derive root + blob dir from a database path.
    ///
    /// If the DB already lives under a directory named `.blackbox`, blobs sit
    /// next to it (`…/.blackbox/blobs`). Otherwise blobs live in
    /// `<db_parent>/.blackbox/blobs` (legacy layout for `./blackbox.db`).
    pub fn from_db_path(db_path: PathBuf) -> Self {
        let parent = db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let parent_is_blackbox = parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == ".blackbox")
            .unwrap_or(false);

        if parent_is_blackbox {
            Self {
                root: parent.clone(),
                db_path,
                blob_dir: parent.join("blobs"),
            }
        } else {
            let root = parent.join(".blackbox");
            Self {
                root: root.clone(),
                db_path,
                blob_dir: root.join("blobs"),
            }
        }
    }

    /// Ensure root and blob directories exist with owner-only modes (Unix 0700).
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        crate::privacy::ensure_private_dirs(&self.root, &[&self.blob_dir])?;
        Ok(())
    }
}

/// Capture-time policy flags.
#[derive(Debug, Clone)]
pub struct CapturePolicy {
    /// When false (default), secrets are redacted before any write.
    /// When true, raw terminal bytes may be stored as blobs (dangerous).
    pub insecure_raw: bool,
    /// Redaction enabled (normally true).
    pub redact: bool,
    /// Hard observe-only mode: no prompt mutation, no continuity, no env injection.
    pub observe_only: bool,
    /// Process-tree enrichment (dense poll, environ sample, subreaper).
    pub process_dense_poll: bool,
    pub process_environ: bool,
    pub process_subreaper: bool,
    pub env_capture: EnvCaptureMode,
    pub store_git_diffs: bool,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            insecure_raw: false,
            redact: true,
            observe_only: false,
            process_dense_poll: false,
            process_environ: false,
            process_subreaper: true,
            env_capture: EnvCaptureMode::Allowlist,
            store_git_diffs: true,
        }
    }
}

impl CapturePolicy {
    /// Overlay process / privacy capture fields from project CaptureConfig.
    pub fn with_process_from_config(mut self, cfg: &CaptureConfig) -> Self {
        self.process_dense_poll = cfg.process_dense_poll;
        self.process_environ = cfg.process_environ;
        self.process_subreaper = cfg.process_subreaper;
        self.env_capture = cfg.env_capture;
        self.store_git_diffs = cfg.store_git_diffs;
        self
    }
}

// ── Project config (`.blackbox/config.toml`) ──────────────────────

/// Project-local blackbox configuration (daily-driver 0.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlackboxConfig {
    /// When true, `maybe-run` may record matching harnesses under this project.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

fn default_true() -> bool {
    true
}

impl Default for BlackboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capture: CaptureConfig::default(),
            retention: RetentionConfig::default(),
        }
    }
}

/// Top-level product posture for a project.
///
/// Simplifies the capture/continuity flag surface for operators:
/// - `Recorder` — hard observe-only ambient capture (daily-driver default)
/// - `Continuity` — memory bus may inject on explicit `blackbox run`
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProductMode {
    /// Neutral flight recorder (observe-only).
    #[default]
    Recorder,
    /// Continuity / memory bus enabled for explicit runs.
    Continuity,
}

impl ProductMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorder => "recorder",
            Self::Continuity => "continuity",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "recorder" | "observe" | "observe-only" | "observe_only" => Some(Self::Recorder),
            "continuity" | "memory" | "memory-bus" | "memory_bus" => Some(Self::Continuity),
            _ => None,
        }
    }
}

/// Continuity / memory-bus inject mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityMode {
    /// Every record launch injects project memory.
    #[default]
    Always,
    /// Inject only when sticky attention_level != none (1.1-compatible).
    Attention,
    /// No inject / no end-of-run memory I/O.
    Off,
}

impl ContinuityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Attention => "attention",
            Self::Off => "off",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "always" => Some(Self::Always),
            "attention" => Some(Self::Attention),
            "off" | "false" | "0" | "no" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Gate mode for explicit `blackbox run` only (never blocks maybe-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    #[default]
    Off,
    Warn,
    RequireAck,
}

impl GateMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::RequireAck => "require_ack",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "no" => Some(Self::Off),
            "warn" => Some(Self::Warn),
            "require_ack" | "require-ack" | "ack" => Some(Self::RequireAck),
            _ => None,
        }
    }
}

/// Claim conflict policy on explicit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPolicy {
    #[default]
    Warn,
    BlockRecord,
}

impl ClaimPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::BlockRecord => "block_record",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "warn" => Some(Self::Warn),
            "block_record" | "block" => Some(Self::BlockRecord),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptureConfig {
    /// Basenames of commands auto-wrapped by shell functions / maybe-run.
    #[serde(default = "default_wrap")]
    pub wrap: Vec<String>,
    /// Tags applied to ambient (maybe-run) captures.
    #[serde(default = "default_auto_tags")]
    pub default_tags: Vec<String>,
    /// Deprecated alias; when `continuity` key absent, true→attention, false→off.
    #[serde(default = "default_true")]
    pub auto_resume: bool,
    /// Max tokens for auto-resume / memory packs written under `.blackbox/`.
    #[serde(default = "default_resume_tokens")]
    pub resume_max_tokens: u32,
    /// Continuity plane mode (1.2). When absent from TOML, derived from auto_resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<ContinuityMode>,
    /// Memory pack token budget; falls back to resume_max_tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max_tokens: Option<u32>,
    /// Gate mode for explicit blackbox run only.
    #[serde(default)]
    pub gate_mode: GateMode,
    /// Auto-acquire project claim on record launch (default false).
    #[serde(default)]
    pub auto_claim: bool,
    /// Claim TTL seconds when auto_claim or explicit acquire without TTL.
    #[serde(default = "default_claim_ttl")]
    pub claim_ttl_secs: u64,
    /// Soft warn vs block explicit run on claim conflict.
    #[serde(default)]
    pub claim_policy: ClaimPolicy,
    /// Hard observe-only mode: record without mutating prompt, argv, environment,
    /// or session continuity. When true, continuity is effectively off, adapter
    /// prepare_launch is skipped, and no BLACKBOX_* env vars are injected.
    #[serde(default)]
    pub observe_only: bool,
    /// Denser process-tree poll (25–100 ms vs 50–200 ms). Slightly higher CPU.
    #[serde(default)]
    pub process_dense_poll: bool,
    /// Sample child `/proc/<pid>/environ` (redacted) into process events.
    /// Off by default — opt-in because environ can be large/sensitive.
    #[serde(default)]
    pub process_environ: bool,
    /// Linux PR_SET_CHILD_SUBREAPER for best-effort descendant exit codes.
    /// Default true; set false to disable waitpid reaping.
    #[serde(default = "default_true")]
    pub process_subreaper: bool,
    /// Environment capture mode: `allowlist` (default, low residual secrets) or `full`.
    #[serde(default)]
    pub env_capture: EnvCaptureMode,
    /// When false, store only redacted git diff preview + stats (no full diff blob).
    /// Default true for debug fidelity; set false for tighter privacy/disk.
    #[serde(default = "default_true")]
    pub store_git_diffs: bool,
}

/// How much of the process environment is stored at run start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnvCaptureMode {
    /// Only common non-secret keys (PATH, HOME, TERM, CI, …) + BLACKBOX_*.
    #[default]
    Allowlist,
    /// Full environment after name+value redaction.
    Full,
}

impl EnvCaptureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowlist => "allowlist",
            Self::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allowlist" | "allow" | "minimal" | "safe" => Some(Self::Allowlist),
            "full" | "all" | "complete" => Some(Self::Full),
            _ => None,
        }
    }
}

/// Keys retained under [`EnvCaptureMode::Allowlist`] (exact match, case-sensitive
/// for typical Unix names; also any key starting with `BLACKBOX_`).
pub fn env_allowlist_keep(name: &str) -> bool {
    if name.starts_with("BLACKBOX_") {
        return true;
    }
    matches!(
        name,
        "PATH"
            | "HOME"
            | "USER"
            | "USERNAME"
            | "LOGNAME"
            | "SHELL"
            | "TERM"
            | "TERM_PROGRAM"
            | "COLORTERM"
            | "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "PWD"
            | "OLDPWD"
            | "TMPDIR"
            | "TMP"
            | "TEMP"
            | "EDITOR"
            | "VISUAL"
            | "HOSTNAME"
            | "HOST"
            | "CI"
            | "GITHUB_ACTIONS"
            | "GITHUB_WORKFLOW"
            | "GITHUB_REPOSITORY"
            | "GITHUB_REF"
            | "GITHUB_SHA"
            | "RUNNER_OS"
            | "RUNNER_ARCH"
            | "XDG_RUNTIME_DIR"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "XDG_CACHE_HOME"
            | "XDG_SESSION_TYPE"
            | "DISPLAY"
            | "WAYLAND_DISPLAY"
            | "SSH_CONNECTION"
            | "SSH_CLIENT"
            | "SSH_TTY"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
            | "CARGO_HOME"
            | "RUSTUP_HOME"
            | "GOPATH"
            | "GOROOT"
            | "NODE_ENV"
            | "PYTHONPATH"
            | "VIRTUAL_ENV"
            | "CONDA_DEFAULT_ENV"
            | "TZ"
            | "COLUMNS"
            | "LINES"
    ) || name.starts_with("LC_")
        || name.starts_with("XDG_")
}

fn default_wrap() -> Vec<String> {
    vec![
        "claude".into(),
        "codex".into(),
        "aider".into(),
        "cursor".into(),
        "cursor-agent".into(),
        "gemini".into(),
        "opencode".into(),
        "grok".into(),
    ]
}

fn default_auto_tags() -> Vec<String> {
    vec!["auto".into()]
}

fn default_resume_tokens() -> u32 {
    4000
}

fn default_claim_ttl() -> u64 {
    1800
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            wrap: default_wrap(),
            default_tags: default_auto_tags(),
            auto_resume: false,
            resume_max_tokens: default_resume_tokens(),
            // Daily-driver trust default: neutral recorder (not memory bus).
            // Opt into continuity with `enable --continuity always` / `--memory-bus`.
            continuity: Some(ContinuityMode::Off),
            memory_max_tokens: None,
            gate_mode: GateMode::Off,
            auto_claim: false,
            claim_ttl_secs: default_claim_ttl(),
            claim_policy: ClaimPolicy::Warn,
            observe_only: true,
            process_dense_poll: false,
            process_environ: false,
            process_subreaper: true,
            env_capture: EnvCaptureMode::Allowlist,
            store_git_diffs: true,
        }
    }
}

impl CaptureConfig {
    /// Effective continuity mode from config only (no CLI/env).
    ///
    /// Observe-only projects always resolve to Off so the recorder cannot
    /// silently re-enable continuity inject.
    pub fn continuity_from_config(&self) -> ContinuityMode {
        if self.observe_only {
            return ContinuityMode::Off;
        }
        if let Some(c) = self.continuity {
            return c;
        }
        // Key absent: derive from auto_resume (1.1 mental model)
        if self.auto_resume {
            ContinuityMode::Attention
        } else {
            ContinuityMode::Off
        }
    }

    /// Effective product mode from observe_only + continuity.
    pub fn product_mode(&self) -> ProductMode {
        if self.observe_only {
            return ProductMode::Recorder;
        }
        if matches!(
            self.continuity_from_config(),
            ContinuityMode::Always | ContinuityMode::Attention
        ) {
            ProductMode::Continuity
        } else {
            ProductMode::Recorder
        }
    }

    pub fn memory_max_tokens_effective(&self) -> u32 {
        self.memory_max_tokens
            .unwrap_or(self.resume_max_tokens)
            .max(1)
    }
}

/// Resolve effective continuity for this invocation.
///
/// Precedence (highest wins):
/// 1. CLI `--no-auto-resume` → Off; `--auto-resume` → Always
/// 2. Env `BLACKBOX_CONTINUITY=always|attention|off`
/// 3. Env `BLACKBOX_AUTO_RESUME=0|false|off|no` → Off; `=1|true|on|yes` → Attention (if no continuity env)
/// 4. Config `capture.continuity` if present
/// 5. Config derived from `auto_resume`
pub fn resolve_continuity(
    cfg: Option<&BlackboxConfig>,
    cli_no_auto_resume: bool,
    cli_auto_resume: bool,
) -> ContinuityMode {
    if cli_no_auto_resume {
        return ContinuityMode::Off;
    }
    if cli_auto_resume {
        return ContinuityMode::Always;
    }
    if let Ok(v) = std::env::var("BLACKBOX_CONTINUITY") {
        if let Some(m) = ContinuityMode::parse(&v) {
            return m;
        }
    }
    if let Ok(v) = std::env::var("BLACKBOX_AUTO_RESUME") {
        let v = v.to_ascii_lowercase();
        if v == "0" || v == "false" || v == "off" || v == "no" {
            return ContinuityMode::Off;
        }
        if v == "1" || v == "true" || v == "on" || v == "yes" {
            return ContinuityMode::Attention;
        }
    }
    cfg.map(|c| c.capture.continuity_from_config())
        .unwrap_or(ContinuityMode::Off)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_keep_runs")]
    pub keep_runs: u32,
    pub max_age_days: Option<u32>,
    #[serde(default = "default_true")]
    pub auto_gc_blobs: bool,
    /// When true, apply retention automatically after runs (best-effort).
    #[serde(default = "default_true")]
    pub auto_apply: bool,
}

fn default_keep_runs() -> u32 {
    50
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            keep_runs: 50,
            max_age_days: Some(30),
            auto_gc_blobs: true,
            auto_apply: true,
        }
    }
}

impl BlackboxConfig {
    /// Load config from a TOML file. Missing file → `None`.
    pub fn load_from_path(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: BlackboxConfig = toml::from_str(&text)?;
        Ok(Some(cfg))
    }

    /// Write config atomically (best-effort).
    pub fn write_to_path(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

/// Result of shared project + store discovery (K21).
#[derive(Debug, Clone)]
pub struct ProjectDiscovery {
    /// Project root directory (repo root or cwd fallback).
    pub project_root: PathBuf,
    /// Resolved store paths under that project (or override).
    pub paths: BlackboxPaths,
    /// Loaded config when `.blackbox/config.toml` was found.
    pub config: Option<BlackboxConfig>,
}

/// Discover project root, store paths, and optional config.
///
/// Algorithm (daily-driver 0.2):
/// 1. `--store` / `BLACKBOX_DB` override → paths only; project_root = cwd
/// 2. Walk ancestors from `cwd`:
///    - legacy `./blackbox.db` wins (isolated project)
///    - `.blackbox/config.toml` → project store at that root
///    - `.blackbox/blackbox.db` without config → that store
/// 3. Else default `cwd/.blackbox/`
pub fn discover_project(
    cwd: &Path,
    db_override: Option<&Path>,
) -> anyhow::Result<ProjectDiscovery> {
    // Explicit CLI --store
    if let Some(db) = db_override {
        let paths = BlackboxPaths::from_db_path(db.to_path_buf());
        let project_root = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
        let config = BlackboxConfig::load_from_path(&paths.root.join("config.toml"))?;
        return Ok(ProjectDiscovery {
            project_root,
            paths,
            config,
        });
    }

    // BLACKBOX_DB env (same rules as BlackboxPaths::resolve)
    if let Ok(env_db) = std::env::var("BLACKBOX_DB") {
        if !env_db.is_empty() {
            let env_path = PathBuf::from(&env_db);
            if env_path.is_dir() {
                anyhow::bail!("BLACKBOX_DB points to a directory, not a file: {}", env_db);
            }
            if env_path.exists() && !is_readable(&env_path) {
                anyhow::bail!("BLACKBOX_DB is not readable: {}", env_db);
            }
            let paths = BlackboxPaths::from_db_path(env_path);
            let project_root = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
            let config = BlackboxConfig::load_from_path(&paths.root.join("config.toml"))?;
            return Ok(ProjectDiscovery {
                project_root,
                paths,
                config,
            });
        }
    }

    let mut dir = if cwd.exists() {
        cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf())
    } else {
        cwd.to_path_buf()
    };

    loop {
        // Legacy root blackbox.db
        let legacy = dir.join("blackbox.db");
        if legacy.exists() {
            return Ok(ProjectDiscovery {
                project_root: dir.clone(),
                paths: BlackboxPaths::from_db_path(legacy),
                config: BlackboxConfig::load_from_path(&dir.join(".blackbox").join("config.toml"))?,
            });
        }

        let bb = dir.join(".blackbox");
        let config_path = bb.join("config.toml");
        let db_path = bb.join("blackbox.db");

        if config_path.exists() {
            let config = BlackboxConfig::load_from_path(&config_path)?;
            return Ok(ProjectDiscovery {
                project_root: dir.clone(),
                paths: BlackboxPaths {
                    root: bb.clone(),
                    db_path,
                    blob_dir: bb.join("blobs"),
                },
                config,
            });
        }

        if db_path.exists() {
            return Ok(ProjectDiscovery {
                project_root: dir.clone(),
                paths: BlackboxPaths {
                    root: bb.clone(),
                    db_path,
                    blob_dir: bb.join("blobs"),
                },
                config: None,
            });
        }

        // Ascend
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => break,
        }
    }

    // Fallback: cwd default layout
    let project_root = if cwd.exists() {
        cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf())
    } else {
        cwd.to_path_buf()
    };
    let paths = BlackboxPaths::resolve(Some(&project_root), None)?;
    Ok(ProjectDiscovery {
        project_root,
        paths,
        config: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn from_db_path_legacy_cwd() {
        let p = BlackboxPaths::from_db_path(PathBuf::from("/tmp/proj/blackbox.db"));
        assert_eq!(p.blob_dir, PathBuf::from("/tmp/proj/.blackbox/blobs"));
    }

    #[test]
    fn from_db_path_nested_blackbox() {
        let p = BlackboxPaths::from_db_path(PathBuf::from("/tmp/proj/.blackbox/blackbox.db"));
        assert_eq!(p.root, PathBuf::from("/tmp/proj/.blackbox"));
        assert_eq!(p.blob_dir, PathBuf::from("/tmp/proj/.blackbox/blobs"));
    }

    /// Helper: create a temp project dir with optional legacy blackbox.db.
    fn make_project(legacy: bool) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().to_path_buf();
        if legacy {
            fs::write(proj.join("blackbox.db"), b"").unwrap();
        }
        (dir, proj)
    }

    #[test]
    fn resolve_explicit_override_takes_priority() {
        let (_dir, proj) = make_project(true);
        let explicit = proj.join("custom.db");
        let paths = BlackboxPaths::resolve(Some(&proj), Some(&explicit)).unwrap();
        assert_eq!(paths.db_path, explicit);
    }

    #[test]
    fn resolve_env_db_takes_priority_over_legacy() {
        let prev = std::env::var("BLACKBOX_DB").ok();
        let (_dir, proj) = make_project(true);
        let env_db = proj.join("env.db");
        std::env::set_var("BLACKBOX_DB", &env_db);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, env_db);
        std::env::remove_var("BLACKBOX_DB");
        if let Some(val) = prev {
            std::env::set_var("BLACKBOX_DB", val);
        }
    }

    #[test]
    fn resolve_legacy_used_when_present() {
        let (_dir, proj) = make_project(true);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, proj.join("blackbox.db"));
    }

    #[test]
    fn resolve_default_when_nothing_exists() {
        // Guard against BLACKBOX_DB leakage from parallel tests
        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");
        let (_dir, proj) = make_project(false);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, proj.join(".blackbox").join("blackbox.db"));
        assert_eq!(paths.blob_dir, proj.join(".blackbox").join("blobs"));
        if let Some(val) = prev {
            std::env::set_var("BLACKBOX_DB", val);
        }
    }

    #[test]
    fn discover_finds_config_in_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let proj = root.path();
        let child = proj.join("packages").join("api");
        fs::create_dir_all(&child).unwrap();
        let bb = proj.join(".blackbox");
        fs::create_dir_all(&bb).unwrap();
        let cfg = BlackboxConfig::default();
        cfg.write_to_path(&bb.join("config.toml")).unwrap();

        // Clear BLACKBOX_DB so it does not hijack discovery
        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");

        let d = discover_project(&child, None).unwrap();
        assert_eq!(d.project_root, proj.canonicalize().unwrap());
        assert_eq!(d.paths.db_path, bb.join("blackbox.db"));
        assert!(d.config.as_ref().is_some_and(|c| c.enabled));

        if let Some(v) = prev {
            std::env::set_var("BLACKBOX_DB", v);
        }
    }

    #[test]
    fn discover_legacy_subdir_isolates() {
        let root = tempfile::tempdir().unwrap();
        let proj = root.path();
        let child = proj.join("nested");
        fs::create_dir_all(&child).unwrap();
        // Parent has config
        let bb = proj.join(".blackbox");
        fs::create_dir_all(&bb).unwrap();
        BlackboxConfig::default()
            .write_to_path(&bb.join("config.toml"))
            .unwrap();
        // Child has legacy db — wins
        fs::write(child.join("blackbox.db"), b"").unwrap();

        let prev = std::env::var("BLACKBOX_DB").ok();
        std::env::remove_var("BLACKBOX_DB");

        let d = discover_project(&child, None).unwrap();
        assert_eq!(d.project_root, child.canonicalize().unwrap());
        assert_eq!(d.paths.db_path, child.join("blackbox.db"));

        if let Some(v) = prev {
            std::env::set_var("BLACKBOX_DB", v);
        }
    }

    #[test]
    fn config_round_trip_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = BlackboxConfig::default();
        cfg.capture.wrap = vec!["claude".into()];
        cfg.write_to_path(&path).unwrap();
        let loaded = BlackboxConfig::load_from_path(&path).unwrap().unwrap();
        assert_eq!(loaded.capture.wrap, vec!["claude".to_string()]);
        assert!(loaded.enabled);
    }
}
