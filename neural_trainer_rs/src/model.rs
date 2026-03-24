//! Learning model that maps signature features → best attack strategy.
//!
//! This implements a decision-tree-like classifier that learns from synthetic
//! training data which feature patterns predict which attack will succeed.
//! The output is a set of rules that can be applied to real-world signatures.

use serde::{Serialize, Deserialize};
use crate::features::ExtendedFeatures;

/// A learned rule: "if features match this pattern, try this attack"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRule {
    pub name: String,
    pub attack_type: String,
    pub conditions: Vec<Condition>,
    pub confidence: f64,  // fraction of training examples where this rule succeeded
    pub support: usize,   // number of training examples
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub feature_name: String,
    pub op: CompareOp,
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompareOp {
    GreaterThan,
    LessThan,
    Equals,
}

impl Condition {
    fn test(&self, value: f64) -> bool {
        match self.op {
            CompareOp::GreaterThan => value > self.threshold,
            CompareOp::LessThan => value < self.threshold,
            CompareOp::Equals => (value - self.threshold).abs() < 1e-9,
        }
    }
}

/// A training record: features + which attacks succeeded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingRecord {
    pub wallet_id: String,
    pub weakness_type: String,
    pub summary_features: Vec<f64>,
    pub successful_attacks: Vec<String>,
    pub failed_attacks: Vec<String>,
}

/// The learned model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedModel {
    pub rules: Vec<AttackRule>,
    pub feature_importance: Vec<(String, f64)>,
    pub training_stats: TrainingStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingStats {
    pub total_wallets: usize,
    pub total_attacks_tried: usize,
    pub total_attacks_succeeded: usize,
    pub per_attack_success: Vec<(String, usize, usize)>, // (attack, succeeded, total)
    pub per_weakness_recovery: Vec<(String, usize, usize)>, // (weakness, recovered, total)
}

const FEATURE_NAMES: &[&str] = &[
    "num_sigs",
    "mean_bit_deviation",
    "max_bit_deviation",
    "num_biased_bits",
    "mean_byte_entropy",
    "min_byte_entropy",
    "short_r_fraction",
    "mean_r_bit_length",
    "max_autocorrelation",
    "max_fft_magnitude",
    "has_r_reuse",
    "min_delta_bits",
    "lsb_bias_fraction",
];

impl LearnedModel {
    /// Build the model from training records
    pub fn train(records: &[TrainingRecord]) -> Self {
        let mut rules = Vec::new();

        // Collect per-attack statistics
        let mut attack_stats: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();
        let mut weakness_stats: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

        for rec in records {
            let any_success = !rec.successful_attacks.is_empty();
            let ws = weakness_stats.entry(rec.weakness_type.clone()).or_insert((0, 0));
            ws.1 += 1;
            if any_success { ws.0 += 1; }

            for atk in &rec.successful_attacks {
                let s = attack_stats.entry(atk.clone()).or_insert((0, 0));
                s.0 += 1;
                s.1 += 1;
            }
            for atk in &rec.failed_attacks {
                let s = attack_stats.entry(atk.clone()).or_insert((0, 0));
                s.1 += 1;
            }
        }

        // Learn rules per attack type via threshold optimization
        let attack_types: Vec<String> = attack_stats.keys().cloned().collect();
        for attack in &attack_types {
            let successes: Vec<&TrainingRecord> = records.iter()
                .filter(|r| r.successful_attacks.contains(attack))
                .collect();
            let failures: Vec<&TrainingRecord> = records.iter()
                .filter(|r| r.failed_attacks.contains(attack))
                .collect();

            if successes.is_empty() { continue; }

            // For each feature, find the threshold that best separates success from failure
            for (fi, fname) in FEATURE_NAMES.iter().enumerate() {
                if fi >= successes[0].summary_features.len() { break; }

                let mut best_threshold = 0.0;
                let mut best_op = CompareOp::GreaterThan;
                let mut best_score = 0.0f64;
                let mut best_conf = 0.0;
                let mut best_support = 0;

                // Collect all threshold candidates
                let mut vals: Vec<f64> = successes.iter().chain(failures.iter())
                    .map(|r| r.summary_features[fi])
                    .collect();
                vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                vals.dedup();

                for &thresh in &vals {
                    for op in [CompareOp::GreaterThan, CompareOp::LessThan] {
                        let cond = Condition { feature_name: fname.to_string(), op: op.clone(), threshold: thresh };
                        let tp = successes.iter().filter(|r| cond.test(r.summary_features[fi])).count();
                        let fp = failures.iter().filter(|r| cond.test(r.summary_features[fi])).count();
                        let total_pos = tp + fp;
                        if total_pos == 0 { continue; }

                        let precision = tp as f64 / total_pos as f64;
                        let recall = tp as f64 / successes.len().max(1) as f64;
                        let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };

                        if f1 > best_score && precision > 0.5 && total_pos >= 3 {
                            best_score = f1;
                            best_threshold = thresh;
                            best_op = op;
                            best_conf = precision;
                            best_support = total_pos;
                        }
                    }
                }

                if best_score > 0.3 && best_support >= 3 {
                    rules.push(AttackRule {
                        name: format!("{}_{}", attack, fname),
                        attack_type: attack.clone(),
                        conditions: vec![Condition {
                            feature_name: fname.to_string(),
                            op: best_op,
                            threshold: best_threshold,
                        }],
                        confidence: best_conf,
                        support: best_support,
                    });
                }
            }
        }

        // Sort rules by confidence (highest first)
        rules.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        // Compute feature importance: how often each feature appears in high-confidence rules
        let mut importance: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        for rule in &rules {
            for cond in &rule.conditions {
                *importance.entry(cond.feature_name.clone()).or_insert(0.0) += rule.confidence;
            }
        }
        let mut feature_importance: Vec<(String, f64)> = importance.into_iter().collect();
        feature_importance.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let per_attack_success: Vec<(String, usize, usize)> = attack_stats.into_iter()
            .map(|(k, (s, t))| (k, s, t))
            .collect();

        let per_weakness_recovery: Vec<(String, usize, usize)> = weakness_stats.into_iter()
            .map(|(k, (s, t))| (k, s, t))
            .collect();

        let total_attacks_succeeded = records.iter().map(|r| r.successful_attacks.len()).sum();
        let total_attacks_tried = records.iter()
            .map(|r| r.successful_attacks.len() + r.failed_attacks.len())
            .sum();

        LearnedModel {
            rules,
            feature_importance,
            training_stats: TrainingStats {
                total_wallets: records.len(),
                total_attacks_tried,
                total_attacks_succeeded,
                per_attack_success,
                per_weakness_recovery,
            },
        }
    }

    /// Given features from a real address, recommend attacks in priority order
    pub fn recommend_attacks(&self, features: &ExtendedFeatures) -> Vec<(String, f64)> {
        let summary = features.summary_vector();
        let mut attack_scores: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

        for rule in &self.rules {
            let all_match = rule.conditions.iter().all(|cond| {
                let fi = FEATURE_NAMES.iter().position(|&n| n == cond.feature_name);
                fi.map(|i| cond.test(summary[i])).unwrap_or(false)
            });

            if all_match {
                let entry = attack_scores.entry(rule.attack_type.clone()).or_insert(0.0);
                *entry = entry.max(rule.confidence);
            }
        }

        let mut recommendations: Vec<(String, f64)> = attack_scores.into_iter().collect();
        recommendations.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        recommendations
    }

    /// Print a human-readable report
    pub fn print_report(&self) {
        println!("\n{}", "=".repeat(60));
        println!("NEURAL TRAINER - LEARNED MODEL REPORT");
        println!("{}", "=".repeat(60));

        println!("\n--- Training Statistics ---");
        println!("  Total wallets:     {}", self.training_stats.total_wallets);
        println!("  Attacks tried:     {}", self.training_stats.total_attacks_tried);
        println!("  Attacks succeeded: {}", self.training_stats.total_attacks_succeeded);

        println!("\n--- Per-Weakness Recovery Rate ---");
        let mut wk = self.training_stats.per_weakness_recovery.clone();
        wk.sort_by(|a, b| b.2.cmp(&a.2));
        for (weakness, recovered, total) in &wk {
            let rate = if *total > 0 { *recovered as f64 / *total as f64 * 100.0 } else { 0.0 };
            println!("  {:25} {}/{} ({:.1}%)", weakness, recovered, total, rate);
        }

        println!("\n--- Per-Attack Success Rate ---");
        let mut ak = self.training_stats.per_attack_success.clone();
        ak.sort_by(|a, b| b.1.cmp(&a.1));
        for (attack, succeeded, total) in &ak {
            let rate = if *total > 0 { *succeeded as f64 / *total as f64 * 100.0 } else { 0.0 };
            println!("  {:25} {}/{} ({:.1}%)", attack, succeeded, total, rate);
        }

        println!("\n--- Feature Importance ---");
        for (fname, score) in self.feature_importance.iter().take(10) {
            println!("  {:25} {:.3}", fname, score);
        }

        println!("\n--- Top Learned Rules (by confidence) ---");
        for rule in self.rules.iter().take(20) {
            let conds: Vec<String> = rule.conditions.iter().map(|c| {
                let op_str = match c.op {
                    CompareOp::GreaterThan => ">",
                    CompareOp::LessThan => "<",
                    CompareOp::Equals => "==",
                };
                format!("{} {} {:.4}", c.feature_name, op_str, c.threshold)
            }).collect();
            println!("  [{:.0}% conf, {} support] {} => {}",
                rule.confidence * 100.0, rule.support,
                conds.join(" AND "), rule.attack_type);
        }
    }
}
