//! Simple, defensible statistics for experiment reports.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalNote {
    pub sample_size: usize,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn median_f64(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    if n % 2 == 1 {
        Some(values[n / 2])
    } else {
        Some((values[n / 2 - 1] + values[n / 2]) / 2.0)
    }
}

/// Nearest-rank percentile (p in 0..=100).
pub fn percentile(values: &mut [f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p = p.clamp(0.0, 100.0);
    let rank = ((p / 100.0) * (values.len() as f64 - 1.0)).round() as usize;
    Some(values[rank.min(values.len() - 1)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_and_p95() {
        let mut v = vec![1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(median_f64(&mut v.clone()), Some(3.0));
        assert!(percentile(&mut v, 95.0).unwrap() >= 4.0);
    }
}
