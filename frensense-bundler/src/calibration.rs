use frensense_engine::corpus::pattern::CorpusPattern;
use frensense_engine::per_pattern_calibration::CalibrationParams;
use std::collections::HashMap;

use frensense_engine::fingerprint::FunctionFingerprint;

pub fn train_per_pattern_calibration(
    patterns: &[CorpusPattern],
) -> HashMap<String, CalibrationParams> {
    let mut result = HashMap::new();

    for pattern in patterns {
        let pos = &pattern.positives;
        let neg = &pattern.negatives;

        // Need enough examples for meaningful split
        if pos.len() < MIN_EXAMPLES || neg.len() < MIN_EXAMPLES {
            continue;
        }

        // Simple 80/20 split: use first 80% as train, last 20% as validate
        let split = (pos.len() as f64 * 0.8).ceil() as usize;
        if split == 0 || split >= pos.len() {
            continue;
        }

        let train_pos: Vec<&FunctionFingerprint> = pos.iter().take(split).collect();
        let val_pos: Vec<&FunctionFingerprint> = pos.iter().skip(split).collect();
        let train_pos_owned: Vec<FunctionFingerprint> =
            train_pos.iter().map(|f| (*f).clone()).collect();
        let val_fps: Vec<&FunctionFingerprint> =
            val_pos.iter().copied().chain(neg.iter()).collect();
        let labels: Vec<f64> = val_pos
            .iter()
            .map(|_| 1.0)
            .chain(neg.iter().map(|_| 0.0))
            .collect();

        // Score each validation fingerprint against the training positives
        let mut scores: Vec<(f64, f64)> = Vec::new();
        for (i, fp) in val_fps.iter().enumerate() {
            // Compute raw feature score
            let mut best = 0.0f64;
            for train in &train_pos_owned {
                let sim = frensense_engine::per_pattern_calibration::compute_calibration_features(
                    fp, train,
                );
                if sim > best {
                    best = sim;
                }
            }
            scores.push((best, labels[i]));
        }

        if scores.len() < MIN_EXAMPLES {
            continue;
        }

        // Fit sigmoid: P(tp) = 1 / (1 + exp(-(A * score + B)))
        // Gradient descent on binary cross-entropy
        let mut a = 1.0f64;
        let mut b = 0.0f64;
        let lr = 0.1;
        let iterations = 500;

        for _ in 0..iterations {
            let mut grad_a = 0.0f64;
            let mut grad_b = 0.0f64;
            for (score, label) in &scores {
                let z = a * score + b;
                let p = 1.0 / (1.0 + (-z).exp());
                let error = p - label;
                grad_a += error * score;
                grad_b += error;
            }
            let n = scores.len() as f64;
            grad_a += 0.01 * a;
            grad_b += 0.01 * b;
            a -= lr * grad_a / n;
            b -= lr * grad_b / n;
        }

        result.insert(pattern.id.clone(), (a as f32, b as f32));
    }

    result
}

const MIN_EXAMPLES: usize = 10;
