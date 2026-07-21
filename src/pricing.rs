//! Optional model pricing for `estimated_cost_usd`.
//!
//! **Off by default.** Never invent prices when disabled or when the model
//! is unknown.
//!
//! Enable with:
//! - `BLACKBOX_ESTIMATE_COST=1`
//! - and/or a rates file via `BLACKBOX_PRICING=/path/to/pricing.toml`
//!   or project `.blackbox/pricing.toml` (loaded when estimating if present)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// USD per 1M tokens.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
pub struct ModelRate {
    /// Input per mtok.
    pub input_per_mtok: f64,
    /// Output per mtok.
    pub output_per_mtok: f64,
}

/// File format for custom pricing tables.
///
/// ```toml
/// [models."claude-sonnet-4"]
/// input_per_mtok = 3.0
/// output_per_mtok = 15.0
///
/// # or flat table:
/// # [models]
/// # "gpt-4o-mini" = { input_per_mtok = 0.15, output_per_mtok = 0.60 }
/// ```
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct PricingFile {
    #[serde(default)]
    /// Models.
    pub models: HashMap<String, ModelRate>,
}

/// Built-in table (approximate public list prices; best-effort only).
fn builtin_rates() -> &'static [(&'static str, ModelRate)] {
    static RATES: OnceLock<Vec<(&'static str, ModelRate)>> = OnceLock::new();
    RATES
        .get_or_init(|| {
            vec![
                (
                    "claude-opus-4",
                    ModelRate {
                        input_per_mtok: 15.0,
                        output_per_mtok: 75.0,
                    },
                ),
                (
                    "claude-sonnet-4",
                    ModelRate {
                        input_per_mtok: 3.0,
                        output_per_mtok: 15.0,
                    },
                ),
                (
                    "claude-3-5-sonnet",
                    ModelRate {
                        input_per_mtok: 3.0,
                        output_per_mtok: 15.0,
                    },
                ),
                (
                    "claude-3-5-haiku",
                    ModelRate {
                        input_per_mtok: 0.80,
                        output_per_mtok: 4.0,
                    },
                ),
                (
                    "claude-haiku",
                    ModelRate {
                        input_per_mtok: 0.80,
                        output_per_mtok: 4.0,
                    },
                ),
                (
                    "gpt-4o",
                    ModelRate {
                        input_per_mtok: 2.50,
                        output_per_mtok: 10.0,
                    },
                ),
                (
                    "gpt-4o-mini",
                    ModelRate {
                        input_per_mtok: 0.15,
                        output_per_mtok: 0.60,
                    },
                ),
                (
                    "o1",
                    ModelRate {
                        input_per_mtok: 15.0,
                        output_per_mtok: 60.0,
                    },
                ),
                (
                    "o3-mini",
                    ModelRate {
                        input_per_mtok: 1.10,
                        output_per_mtok: 4.40,
                    },
                ),
                (
                    "gemini-2.0-flash",
                    ModelRate {
                        input_per_mtok: 0.10,
                        output_per_mtok: 0.40,
                    },
                ),
                (
                    "gemini-1.5-pro",
                    ModelRate {
                        input_per_mtok: 1.25,
                        output_per_mtok: 5.0,
                    },
                ),
                (
                    "grok-3",
                    ModelRate {
                        input_per_mtok: 3.0,
                        output_per_mtok: 15.0,
                    },
                ),
                (
                    "grok-2",
                    ModelRate {
                        input_per_mtok: 2.0,
                        output_per_mtok: 10.0,
                    },
                ),
            ]
        })
        .as_slice()
}

type CustomRatesCache = Option<(PathBuf, HashMap<String, ModelRate>)>;

/// Cached custom rates from file (path → rates). Cleared when path changes.
static CUSTOM_CACHE: OnceLock<Mutex<CustomRatesCache>> = OnceLock::new();

fn custom_cache() -> &'static Mutex<CustomRatesCache> {
    CUSTOM_CACHE.get_or_init(|| Mutex::new(None))
}

/// Resolve pricing file path: `BLACKBOX_PRICING`, else `.blackbox/pricing.toml` under cwd
/// (and optional project hint).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `resolve_pricing_path` — see module docs for full workflow.
/// ```
pub fn resolve_pricing_path(project_root: Option<&Path>) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BLACKBOX_PRICING") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let candidates = [
        project_root.map(|r| r.join(".blackbox/pricing.toml")),
        std::env::current_dir()
            .ok()
            .map(|c| c.join(".blackbox/pricing.toml")),
    ];
    candidates.into_iter().flatten().find(|c| c.is_file())
}

/// Load a pricing.toml file.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `load_pricing_file` — see module docs for full workflow.
/// ```
pub fn load_pricing_file(path: &Path) -> anyhow::Result<PricingFile> {
    let text = std::fs::read_to_string(path)?;
    let parsed: PricingFile = toml::from_str(&text)?;
    Ok(parsed)
}

fn custom_rates() -> HashMap<String, ModelRate> {
    let Some(path) = resolve_pricing_path(None) else {
        return HashMap::new();
    };
    let mut guard = custom_cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some((ref cached_path, ref rates)) = *guard {
        if cached_path == &path {
            return rates.clone();
        }
    }
    match load_pricing_file(&path) {
        Ok(file) => {
            let rates = file.models;
            *guard = Some((path, rates.clone()));
            rates
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "failed to load pricing file");
            HashMap::new()
        }
    }
}

/// True when cost estimation is enabled via env.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `estimate_cost_enabled` — see module docs for full workflow.
/// ```
pub fn estimate_cost_enabled() -> bool {
    std::env::var("BLACKBOX_ESTIMATE_COST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// Look up a rate by model id (custom file first, then builtin).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `rate_for_model` — see module docs for full workflow.
/// ```
pub fn rate_for_model(model: &str) -> Option<ModelRate> {
    let m = model.to_ascii_lowercase();

    // Custom file: exact or substring match, prefer longest key
    let custom = custom_rates();
    let mut best: Option<(usize, ModelRate)> = None;
    for (key, rate) in &custom {
        let k = key.to_ascii_lowercase();
        if m.contains(&k) || m.starts_with(&k) || k.contains(&m) {
            let score = k.len();
            if best.as_ref().is_none_or(|(s, _)| score > *s) {
                best = Some((score, *rate));
            }
        }
    }
    if let Some((_, r)) = best {
        return Some(r);
    }

    let mut best_b: Option<(&str, ModelRate)> = None;
    for (key, rate) in builtin_rates() {
        if (m.contains(key) || m.starts_with(key))
            && best_b.as_ref().is_none_or(|(k, _)| key.len() > k.len())
        {
            best_b = Some((key, *rate));
        }
    }
    best_b.map(|(_, r)| r)
}

/// Estimate USD cost from token counts. Returns `None` if model unknown
/// or tokens missing (never invents a price).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `estimate_cost_usd` — see module docs for full workflow.
/// ```
pub fn estimate_cost_usd(
    model: Option<&str>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
) -> Option<f64> {
    let model = model?;
    let rate = rate_for_model(model)?;
    let input = input_tokens.unwrap_or(0) as f64;
    let output = output_tokens.unwrap_or(0) as f64;
    if input == 0.0 && output == 0.0 {
        return None;
    }
    let cost =
        (input / 1_000_000.0) * rate.input_per_mtok + (output / 1_000_000.0) * rate.output_per_mtok;
    Some((cost * 1_000_000.0).round() / 1_000_000.0)
}

/// Apply estimation when enabled; leave `None` when disabled or unknown.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `maybe_estimate` — see module docs for full workflow.
/// ```
pub fn maybe_estimate(
    model: Option<&str>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
) -> Option<f64> {
    if !estimate_cost_enabled() {
        return None;
    }
    estimate_cost_usd(model, input_tokens, output_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn unknown_model_returns_none() {
        assert!(estimate_cost_usd(Some("mystery-model-xyz"), Some(1000), Some(1000)).is_none());
    }

    #[test]
    fn known_model_computes() {
        let c = estimate_cost_usd(
            Some("gpt-4o-mini-2024-07-18"),
            Some(1_000_000),
            Some(1_000_000),
        )
        .unwrap();
        assert!((c - 0.75).abs() < 1e-9);
    }

    #[test]
    fn disabled_by_default() {
        assert!(estimate_cost_usd(None, Some(100), Some(100)).is_none());
    }

    #[test]
    fn substring_match_claude_sonnet() {
        assert!(rate_for_model("claude-sonnet-4-20250514").is_some());
    }

    #[test]
    fn custom_pricing_file_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pricing.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[models."custom-model-xyz"]
input_per_mtok = 1.0
output_per_mtok = 2.0
"#
        )
        .unwrap();

        let prev = std::env::var("BLACKBOX_PRICING").ok();
        std::env::set_var("BLACKBOX_PRICING", &path);
        // bust cache
        if let Ok(mut g) = custom_cache().lock() {
            *g = None;
        }

        let rate = rate_for_model("custom-model-xyz-v1").expect("custom rate");
        assert!((rate.input_per_mtok - 1.0).abs() < 1e-9);
        let cost =
            estimate_cost_usd(Some("custom-model-xyz"), Some(1_000_000), Some(1_000_000)).unwrap();
        assert!((cost - 3.0).abs() < 1e-9);

        match prev {
            Some(v) => std::env::set_var("BLACKBOX_PRICING", v),
            None => std::env::remove_var("BLACKBOX_PRICING"),
        }
        if let Ok(mut g) = custom_cache().lock() {
            *g = None;
        }
    }
}
