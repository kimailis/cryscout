//! CryScout Neural Trainer
//!
//! A self-contained training ground for learning ECDSA vulnerability patterns.
//!
//! Workflow:
//! 1. Generate synthetic wallets with known weakness types
//! 2. Extract features from their signatures
//! 3. Run all attack algorithms against each wallet
//! 4. Learn which features predict which attack success
//! 5. Output a model that can be applied to real signatures
//!
//! Uses a separate database (neural_trainer.db), never touches cryscout.db.

mod generator;
mod features;
mod solver;
mod model;

use anyhow::Result;
use num_integer::Integer;
use num_traits::Num;
use rusqlite::{params, Connection};
use std::time::Instant;

const DB_FILE: &str = "neural_trainer.db";

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE,
            privkey_hex TEXT,
            weakness_type TEXT,
            weakness_params TEXT,
            num_sigs INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_address TEXT,
            r_hex TEXT,
            s_hex TEXT,
            z_hex TEXT,
            k_hex TEXT,
            FOREIGN KEY (wallet_address) REFERENCES wallets(address)
        );

        CREATE TABLE IF NOT EXISTS attack_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_address TEXT,
            attack_type TEXT,
            success BOOLEAN,
            recovered_key TEXT,
            time_ms INTEGER,
            FOREIGN KEY (wallet_address) REFERENCES wallets(address)
        );

        CREATE TABLE IF NOT EXISTS feature_vectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wallet_address TEXT UNIQUE,
            features_json TEXT,
            summary_json TEXT,
            FOREIGN KEY (wallet_address) REFERENCES wallets(address)
        );

        CREATE TABLE IF NOT EXISTS learned_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_json TEXT,
            trained_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_sigs_wallet ON signatures(wallet_address);
        CREATE INDEX IF NOT EXISTS idx_results_wallet ON attack_results(wallet_address);
    ")?;
    Ok(())
}

fn save_wallet(conn: &Connection, wallet: &generator::SyntheticWallet) -> Result<()> {
    let n = num_bigint::BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    ).unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO wallets (address, privkey_hex, weakness_type, weakness_params, num_sigs)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            wallet.address,
            wallet.privkey_hex,
            wallet.weakness_type.to_string(),
            wallet.weakness_params,
            wallet.signatures.len() as i64,
        ],
    )?;

    for sig in &wallet.signatures {
        conn.execute(
            "INSERT INTO signatures (wallet_address, r_hex, s_hex, z_hex, k_hex)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                wallet.address,
                format!("{:064x}", sig.r.mod_floor(&n)),
                format!("{:064x}", sig.s.mod_floor(&n)),
                format!("{:064x}", sig.z.mod_floor(&n)),
                format!("{:064x}", sig.k.mod_floor(&n)),
            ],
        )?;
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("CryScout Neural Trainer v1.0");
    println!("============================");
    println!("Separate training database: {}", DB_FILE);

    let conn = Connection::open(DB_FILE)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", &30000)?;
    init_db(&conn)?;

    let total_start = Instant::now();

    // === Phase 1: Generate synthetic wallets ===
    println!("\n[Phase 1] Generating synthetic training data...");
    let phase1_start = Instant::now();
    let mut rng = rand::thread_rng();
    let wallets = generator::generate_training_set(&mut rng);

    // Save to DB
    for wallet in &wallets {
        save_wallet(&conn, wallet)?;
    }
    println!("[Phase 1] Done in {:.1}s — {} wallets saved to DB",
        phase1_start.elapsed().as_secs_f64(), wallets.len());

    // === Phase 2: Extract features ===
    println!("\n[Phase 2] Extracting features...");
    let phase2_start = Instant::now();
    let mut feature_count = 0;

    for wallet in &wallets {
        let r_values: Vec<num_bigint::BigInt> = wallet.signatures.iter()
            .map(|s| s.r.clone())
            .collect();

        if let Some(ext_feats) = features::ExtendedFeatures::extract(&r_values) {
            let features_json = serde_json::to_string(&ext_feats.base)?;
            let summary_json = serde_json::to_string(&ext_feats.summary_vector())?;
            conn.execute(
                "INSERT OR REPLACE INTO feature_vectors (wallet_address, features_json, summary_json)
                 VALUES (?1, ?2, ?3)",
                params![wallet.address, features_json, summary_json],
            )?;
            feature_count += 1;
        }
    }
    println!("[Phase 2] Done in {:.1}s — {} feature vectors extracted",
        phase2_start.elapsed().as_secs_f64(), feature_count);

    // === Phase 3: Run attacks ===
    println!("\n[Phase 3] Running attack algorithms...");
    let phase3_start = Instant::now();
    let mut total_attacks = 0;
    let mut total_successes = 0;
    let mut training_records = Vec::new();

    for (wi, wallet) in wallets.iter().enumerate() {
        if wallet.signatures.len() < 2 { continue; }

        let results = solver::run_all_attacks(&wallet.signatures, &wallet.privkey);

        let mut successful_attacks = Vec::new();
        let mut failed_attacks = Vec::new();

        for result in &results {
            conn.execute(
                "INSERT INTO attack_results (wallet_address, attack_type, success, recovered_key, time_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    wallet.address,
                    result.attack_type,
                    result.success,
                    result.recovered_key.as_deref(),
                    result.time_ms as i64,
                ],
            )?;

            total_attacks += 1;
            if result.success {
                total_successes += 1;
                successful_attacks.push(result.attack_type.clone());
            } else {
                failed_attacks.push(result.attack_type.clone());
            }
        }

        // Build training record
        let r_values: Vec<num_bigint::BigInt> = wallet.signatures.iter()
            .map(|s| s.r.clone())
            .collect();
        if let Some(ext_feats) = features::ExtendedFeatures::extract(&r_values) {
            training_records.push(model::TrainingRecord {
                wallet_id: wallet.address.clone(),
                weakness_type: wallet.weakness_type.to_string(),
                summary_features: ext_feats.summary_vector(),
                successful_attacks,
                failed_attacks,
            });
        }

        if (wi + 1) % 50 == 0 || wi + 1 == wallets.len() {
            print!("  [{}/{}] {} attacks, {} successes\r",
                wi + 1, wallets.len(), total_attacks, total_successes);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
    println!("\n[Phase 3] Done in {:.1}s — {}/{} attacks succeeded ({:.1}%)",
        phase3_start.elapsed().as_secs_f64(),
        total_successes, total_attacks,
        total_successes as f64 / total_attacks.max(1) as f64 * 100.0);

    // === Phase 4: Train model ===
    println!("\n[Phase 4] Training model...");
    let phase4_start = Instant::now();
    let learned_model = model::LearnedModel::train(&training_records);

    // Save model to DB
    let model_json = serde_json::to_string_pretty(&learned_model)?;
    conn.execute(
        "INSERT INTO learned_rules (model_json) VALUES (?1)",
        params![model_json],
    )?;

    // Also save to file for easy inspection
    std::fs::write("neural_trainer_model.json", &model_json)?;

    println!("[Phase 4] Done in {:.1}s", phase4_start.elapsed().as_secs_f64());

    // === Print report ===
    learned_model.print_report();

    println!("\n============================");
    println!("Total time: {:.1}s", total_start.elapsed().as_secs_f64());
    println!("Model saved to: neural_trainer_model.json");
    println!("Database: {}", DB_FILE);
    println!("============================");

    Ok(())
}
