// SPDX-License-Identifier: Apache-2.0
//! Latency summaries: nearest-rank percentiles over the recorded samples.

use crate::load::Samples;
use serde::{Deserialize, Serialize};

/// One run's latency distribution, in microseconds, and its throughput.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    /// Calls that came back correct (the samples).
    pub n: usize,
    /// Calls that failed or came back wrong. Not in the percentiles.
    pub errors: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    /// Correct calls per second of wall time.
    pub rps: f64,
}

pub fn summarize(samples: &Samples) -> Summary {
    let mut sorted = samples.micros.clone();
    sorted.sort_unstable();
    let n = sorted.len();
    let secs = samples.wall.as_secs_f64();
    Summary {
        n,
        errors: samples.errors,
        min_us: sorted.first().copied().unwrap_or(0),
        p50_us: percentile(&sorted, 50.0),
        p90_us: percentile(&sorted, 90.0),
        p99_us: percentile(&sorted, 99.0),
        max_us: sorted.last().copied().unwrap_or(0),
        mean_us: if n == 0 {
            0
        } else {
            sorted.iter().sum::<u64>() / n as u64
        },
        rps: if secs > 0.0 { n as f64 / secs } else { 0.0 },
    }
}

/// The nearest-rank percentile of `sorted` (ascending): the smallest sample with
/// at least `p` percent of the samples at or below it. `0` for no samples.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn nearest_rank_percentiles() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50.0), 50);
        assert_eq!(percentile(&v, 99.0), 99);
        assert_eq!(percentile(&v, 100.0), 100);
        assert_eq!(percentile(&v, 0.0), 1);
        assert_eq!(percentile(&[7], 99.0), 7);
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn a_summary_reads_unsorted_samples() {
        let samples = Samples {
            micros: vec![30, 10, 20, 40],
            errors: 2,
            wall: Duration::from_secs(2),
        };
        let s = summarize(&samples);
        assert_eq!((s.n, s.errors), (4, 2));
        assert_eq!((s.min_us, s.p50_us, s.max_us), (10, 20, 40));
        assert_eq!(s.mean_us, 25);
        assert!((s.rps - 2.0).abs() < 1e-9);
    }
}
