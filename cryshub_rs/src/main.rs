use anyhow::Result;
use chrono::Local;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tokio::time;

const STATUS_FILE: &str = "service_status.json";
const SIGNAL_FILE: &str = "service_signal.txt";
const DB_FILE: &str = "cryscout.db";
const MAX_CPU_FOR_SPAWN: f32 = 70.0;
const MAX_RAM_FOR_SPAWN: f64 = 85.0;
const GLOBAL_CPU_CAP: f32 = 85.0;
const RESTART_CPU_THRESHOLD: f32 = 70.0;
const LOW_PRIORITY_WORKERS: &[&str] = &["scouter", "neural_scout", "weak_key_scanner", "treasure_hunter", "brainwallet"];

const CRASH_LOOP_UPTIME_SECS: f64 = 60.0;
const INITIAL_RESTART_BACKOFF_SECS: u64 = 5;
const MAX_RESTART_BACKOFF_SECS: u64 = 300;
const STARTUP_STAGGER_MS: u64 = 1000;

// Note: fetcher and treasure_hunter managed manually to control API rate limits
const WORKER_TYPES: &[&str] = &["scanner", "analyzer", "striker", "scouter"];

const DASHBOARD_UPDATE_INTERVAL: u64 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WorkerDetail {
    id: String,
    task: String,
    cpu: f64,
    ram: f64,
    last_seen: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct HubStatus {
    running: bool,
    current_task: String,
    cpu_usage: f64,
    ram_usage: f64,
    last_heartbeat: f64,
    last_update: String,
    pid: u32,
    logs: Vec<String>,
    worker_count: usize,
    workers_detailed: Vec<WorkerDetail>,
}

struct WorkerInfo {
    _process: Child,
    worker_type: String,
    started_at: f64,
}

#[derive(Clone, Default)]
struct RestartPolicy {
    consecutive_failures: u32,
    next_restart_at: f64,
    suspended: bool,
    suspended_at: f64,
}

const SUSPEND_COOLDOWN_SECS: f64 = 120.0;

struct HubState {
    workers: HashMap<u32, WorkerInfo>,
    restart_policy: HashMap<String, RestartPolicy>,
    running: bool,
    log_buffer: Vec<String>,
}

fn worker_status_id(worker_type: &str, pid: u32) -> String {
    let label = match worker_type {
        "scanner" => "Scanner",
        "analyzer" => "Analyzer",
        "striker" => "Striker",
        "scouter" => "Scouter",
        "fetcher" => "Fetcher",
        "neural_scout" => "NeuralScout",
        "scorer" => "Scorer",
        "weak_key_scanner" => "WeakKeyScanner",
        "treasure_hunter" => "TreasureHunter",
        "brainwallet" => "BrainWallet",
        _ => worker_type,
    };
    format!("{}-{}", label, pid)
}

impl HubState {
    fn new() -> Self {
        Self {
            workers: HashMap::new(),
            restart_policy: HashMap::new(),
            running: true,
            log_buffer: Vec::new(),
        }
    }

    fn log(&mut self, msg: String) {
        let now = Local::now().format("%H:%M:%S").to_string();
        let formatted = format!("[{}] [HUB] {}", now, msg);
        println!("{}", formatted);
        self.log_buffer.push(formatted);
        if self.log_buffer.len() > 500 {
            self.log_buffer.remove(0);
        }
    }
}

async fn get_worker_details() -> Vec<WorkerDetail> {
    tokio::task::spawn_blocking(|| {
        let mut details = Vec::new();
        if let Ok(conn) = Connection::open(DB_FILE) {
            let _ = conn.pragma_update(None, "busy_timeout", &30000);
            let query = "SELECT worker_id, task, cpu_usage, ram_usage, last_heartbeat 
                         FROM worker_status 
                         WHERE last_heartbeat > datetime('now', '-120 seconds')
                         ORDER BY worker_id ASC";
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(iter) = stmt.query_map([], |row| {
                    Ok(WorkerDetail {
                        id: row.get(0)?,
                        task: row.get(1)?,
                        cpu: row.get(2)?,
                        ram: row.get(3)?,
                        last_seen: row.get(4)?,
                    })
                }) {
                    details.extend(iter.flatten());
                }
            }
        }
        details
    }).await.unwrap_or_default()
}

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn restart_backoff_secs(consecutive_failures: u32) -> u64 {
    let exp = consecutive_failures.saturating_sub(1).min(6);
    let raw = INITIAL_RESTART_BACKOFF_SECS.saturating_mul(1u64 << exp);
    raw.min(MAX_RESTART_BACKOFF_SECS)
}

async fn wait_for_spawn_budget(state: Arc<RwLock<HubState>>, worker_type: &str) -> bool {
    let mut system = System::new_all();
    loop {
        let (running, wait_secs, _cpu, _ram) = {
            let s = state.read().await;
            system.refresh_cpu_usage();
            system.refresh_memory();
            let cpu = system.global_cpu_info().cpu_usage();
            let ram = (system.used_memory() as f64 / system.total_memory() as f64) * 100.0;
            let running = s.running;
            
            let suspended = s.restart_policy.get(worker_type).map(|p| p.suspended).unwrap_or(false);
            if suspended {
                (running, 10, cpu, ram)
            } else {
                let restart_wait = s
                    .restart_policy
                    .get(worker_type)
                    .map(|policy| {
                        let now = now_ts();
                        if policy.next_restart_at > now {
                            (policy.next_restart_at - now).ceil() as u64
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);
                let resource_wait = if cpu > MAX_CPU_FOR_SPAWN || ram > MAX_RAM_FOR_SPAWN {
                    10
                } else {
                    0
                };
                (running, restart_wait.max(resource_wait), cpu, ram)
            }
        };

        if !running {
            return false;
        }

        if wait_secs == 0 {
            return true;
        }

        time::sleep(Duration::from_secs(wait_secs.min(10))).await;
    }
}

async fn monitor_resource_budget(state: Arc<RwLock<HubState>>) {
    let mut interval = time::interval(Duration::from_secs(2));
    let mut system = System::new_all();
    loop {
        interval.tick().await;
        
        system.refresh_cpu_usage();
        let cpu = system.global_cpu_info().cpu_usage();

        let mut s = state.write().await;
        if !s.running { continue; }

        if cpu > GLOBAL_CPU_CAP {
            // Find a low priority worker to stop
            let to_stop = s.workers.iter()
                .find(|(_, info)| LOW_PRIORITY_WORKERS.contains(&info.worker_type.as_str()))
                .map(|(pid, info)| (*pid, info.worker_type.clone()));

            if let Some((pid, w_type)) = to_stop {
                s.log(format!("CPU OVER LOAD ({:.1}% > {:.1}%). Suspending low-priority worker {} (PID: {})", cpu, GLOBAL_CPU_CAP, w_type, pid));
                let status_id = worker_status_id(&w_type, pid);
                if let Some(mut info) = s.workers.remove(&pid) {
                    let _ = info._process.kill().await;
                    let policy = s.restart_policy.entry(w_type).or_insert_with(RestartPolicy::default);
                    policy.suspended = true;
                    policy.suspended_at = now_ts();
                }
                // Clean up DB worker_status entry for the killed worker
                if let Ok(conn) = Connection::open(DB_FILE) {
                    let _ = conn.pragma_update(None, "busy_timeout", &5000);
                    let _ = conn.execute(
                        "DELETE FROM worker_status WHERE worker_id = ?1",
                        params![status_id],
                    );
                }
            }
        } else if cpu < RESTART_CPU_THRESHOLD {
            // Check if we can resume a suspended worker (with cooldown to prevent thrashing)
            let now = now_ts();
            let to_resume = s.restart_policy.iter_mut()
                .find(|(_, p)| p.suspended && (now - p.suspended_at) >= SUSPEND_COOLDOWN_SECS)
                .map(|(w_type, p)| {
                    p.suspended = false;
                    w_type.clone()
                });

            if let Some(w_type) = to_resume {
                s.log(format!("CPU load healthy ({:.1}% < {:.1}%). Resuming suspended worker {}", cpu, RESTART_CPU_THRESHOLD, w_type));
                let state_clone = Arc::clone(&state);
                drop(s);
                tokio::spawn(async move {
                    start_worker(state_clone, &w_type).await;
                });
                // Continue monitoring — don't return. Sleep briefly to let CPU settle.
                time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }
    }
}

async fn handle_worker_stream(
    state: Arc<RwLock<HubState>>,
    pid: u32,
    worker_type: String,
    stream_name: &'static str,
    mut stream: impl tokio::io::AsyncRead + Unpin,
) {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let text = line.trim();
                if !text.is_empty() {
                    state.write().await.log(format!("[{}:{}] {}", worker_type, stream_name, text));
                }
            }
            Err(_) => break,
        }
    }
    state.write().await.log(format!(
        "Worker {} (PID: {}) {} stream closed",
        worker_type, pid, stream_name
    ));
}

async fn reap_workers(state: Arc<RwLock<HubState>>) {
    let mut exited = Vec::new();
    let mut poll_errors = Vec::new();
    let should_restart;
    {
        let mut s = state.write().await;
        should_restart = s.running;
        let now = now_ts();
        for (&pid, info) in s.workers.iter_mut() {
            match info._process.try_wait() {
                Ok(Some(status)) => {
                    exited.push((pid, info.worker_type.clone(), status.code(), now - info.started_at));
                }
                Ok(None) => {}
                Err(e) => {
                    poll_errors.push((info.worker_type.clone(), pid, e.to_string()));
                }
            }
        }

        for (worker_type, pid, err) in poll_errors {
            s.log(format!(
                "Failed to poll worker {} (PID: {}): {}",
                worker_type, pid, err
            ));
        }

        for (pid, worker_type, code, uptime) in &exited {
            s.workers.remove(pid);
            let policy = s
                .restart_policy
                .entry(worker_type.clone())
                .or_insert_with(RestartPolicy::default);
            if *uptime < CRASH_LOOP_UPTIME_SECS {
                policy.consecutive_failures = policy.consecutive_failures.saturating_add(1);
                policy.next_restart_at = now + restart_backoff_secs(policy.consecutive_failures) as f64;
            } else {
                policy.consecutive_failures = 0;
                policy.next_restart_at = now;
            }
            s.log(format!(
                "Worker {} (PID: {}) exited with status {:?} after {:.1}s",
                worker_type, pid, code, uptime
            ));
        }
    }

    if exited.is_empty() {
        return;
    }

    if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &30000);
        for (pid, worker_type, _, _) in &exited {
            let _ = conn.execute(
                "DELETE FROM worker_status WHERE worker_id = ?1",
                params![worker_status_id(worker_type, *pid)],
            );
        }
    }

    if should_restart {
        for (_, worker_type, _, _) in exited {
            let state_clone = Arc::clone(&state);
            let worker_type_clone = worker_type.clone();
            tokio::spawn(async move {
                let still_running = state_clone.read().await.running;
                if still_running {
                    let _ = start_worker(state_clone, &worker_type_clone).await;
                }
            });
        }
    }
}

async fn start_worker(state: Arc<RwLock<HubState>>, worker_type: &str) -> Option<u32> {
    if !wait_for_spawn_budget(Arc::clone(&state), worker_type).await {
        return None;
    }

    let worker_binary = match worker_type {
        "scouter" => "./target/release/wallet_scout_rs",
        "fetcher" => "./target/release/address_analyzer_rs",
        "neural_scout" => "./target/release/neural_scout_rs",
        "weak_key_scanner" => "./target/release/weak_key_scanner_rs",
        "treasure_hunter" | "brainwallet" => "python3",
        _ => "./target/release/cryscout_worker_rs",
    };

    let mut command = Command::new(worker_binary);
    if worker_type == "treasure_hunter" {
        command.arg("-u").arg("treasure_hunt.py").arg("500");
    } else if worker_type == "brainwallet" {
        command.arg("-u").arg("brainwallet_attack.py");
    } else if worker_type != "scouter" && worker_type != "neural_scout" && worker_type != "weak_key_scanner" {
        command.arg(worker_type);
    }
    
    let mut child = match command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            state.write().await.log(format!("Failed to start {}: {}.", worker_type, e));
            return None;
        }
    };

    let pid = child.id().unwrap_or(0);
    if pid == 0 { return None; }

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let w_type = worker_type.to_string();

    {
        let mut s = state.write().await;
        s.restart_policy.insert(
            worker_type.to_string(),
            RestartPolicy {
                consecutive_failures: 0,
                next_restart_at: 0.0,
                suspended: false,
                suspended_at: 0.0,
            },
        );
        s.workers.insert(
            pid,
            WorkerInfo {
                _process: child,
                worker_type: w_type.clone(),
                started_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0),
            },
        );
        s.log(format!("Started {} worker (PID: {})", worker_type, pid));
        
        // Immediate DB entry for UI feedback
        if let Ok(conn) = Connection::open(DB_FILE) {
            let _ = conn.pragma_update(None, "busy_timeout", &30000);
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![worker_status_id(worker_type, pid), "Initializing...", 0.0, 0.0],
            );
        }
    }
    
    let state_clone = Arc::clone(&state);
    let w_type_stdout = w_type.clone();
    tokio::spawn(async move {
        handle_worker_stream(state_clone, pid, w_type_stdout, "stdout", stdout).await;
    });

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        handle_worker_stream(state_clone, pid, w_type, "stderr", stderr).await;
    });

    Some(pid)
}

async fn update_dashboard_json(state: Arc<RwLock<HubState>>) {
    // Clean stale worker_status entries (no heartbeat in >5 minutes)
    if let Ok(conn) = Connection::open(DB_FILE) {
        let _ = conn.pragma_update(None, "busy_timeout", &5000);
        let _ = conn.execute(
            "DELETE FROM worker_status WHERE last_heartbeat < datetime('now', '-300 seconds')",
            [],
        );
    }

    let worker_details = get_worker_details().await;
    
    let mut system = System::new_all();
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu_usage = system.global_cpu_info().cpu_usage() as f64;
    let ram_usage = (system.used_memory() as f64 / system.total_memory() as f64) * 100.0;

    let (running, pid, logs) = {
        let s = state.read().await;
        (s.running, std::process::id(), s.log_buffer.clone())
    };
    
    let last_heartbeat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let status = HubStatus {
        running,
        current_task: format!("Hub active: {} workers", worker_details.len()),
        cpu_usage,
        ram_usage,
        last_heartbeat,
        last_update: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        pid,
        logs,
        worker_count: worker_details.len(),
        workers_detailed: worker_details,
    };

    if let Ok(json) = serde_json::to_string_pretty(&status) {
        let _ = fs::write(STATUS_FILE, json);
    }
}

async fn stop_all(state: Arc<RwLock<HubState>>) {
    let mut s = state.write().await;
    if !s.workers.is_empty() {
        let count = s.workers.len();
        s.log(format!("Shutting down fleet: {} active workers.", count));
        
        let pids: Vec<u32> = s.workers.keys().cloned().collect();
        for pid in pids {
            if let Some(mut info) = s.workers.remove(&pid) {
                s.log(format!("Stopping {} (PID: {})", info.worker_type, pid));
                let _ = info._process.kill().await;
            }
        }
        
        if let Ok(conn) = Connection::open(DB_FILE) {
            let _ = conn.pragma_update(None, "busy_timeout", &30000);
            let _ = conn.execute("DELETE FROM worker_status", []);
        }
    }
    s.running = false;
    s.log("Fleet status: IDLE".to_string());
}

async fn check_signals(state: Arc<RwLock<HubState>>) {
    if Path::new(SIGNAL_FILE).exists() {
        if let Ok(sig) = fs::read_to_string(SIGNAL_FILE) {
            let signal = sig.trim();
            if signal.is_empty() { return; }
            
            {
                let mut s = state.write().await;
                s.log(format!("SIGNAL RECEIVED: {}", signal));
            }
            
            // Remove file before acting to avoid loops if action panics
            let _ = fs::remove_file(SIGNAL_FILE);

            if signal == "STOP" {
                stop_all(Arc::clone(&state)).await;
                state.write().await.log("Hub process exiting per STOP signal.".to_string());
                std::process::exit(0);
            } else if signal == "START" || signal == "RESTART" {
                stop_all(Arc::clone(&state)).await;
                
                let mut s = state.write().await;
                s.running = true;
                s.restart_policy.clear();
                s.log("Spawning fresh worker fleet...".to_string());
                drop(s);

                for t in WORKER_TYPES {
                    start_worker(Arc::clone(&state), t).await;
                    time::sleep(Duration::from_millis(STARTUP_STAGGER_MS)).await;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = Arc::new(RwLock::new(HubState::new()));
    println!("[{}] CryScout Hub v3.2 starting up...", Local::now().format("%H:%M:%S"));

    // Cleanup any lingering orphans before starting new fleet
    stop_all(Arc::clone(&state)).await;
    {
        let mut s = state.write().await;
        s.running = true;
        s.log("Initial fleet spawn...".to_string());
    }

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    // Start background management loop BEFORE spawning workers so dashboard updates immediately
    let state_clone_bg = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            // Each operation is isolated so a failure in one doesn't kill the loop
            let sc = Arc::clone(&state_clone_bg);
            if let Err(e) = tokio::spawn(check_signals(sc)).await {
                eprintln!("[HUB] check_signals task failed: {}", e);
            }
            let sc = Arc::clone(&state_clone_bg);
            if let Err(e) = tokio::spawn(reap_workers(sc)).await {
                eprintln!("[HUB] reap_workers task failed: {}", e);
            }
            let sc = Arc::clone(&state_clone_bg);
            if let Err(e) = tokio::spawn(update_dashboard_json(sc)).await {
                eprintln!("[HUB] update_dashboard_json task failed: {}", e);
            }
        }
    });

    let state_clone_resource = Arc::clone(&state);
    tokio::spawn(async move {
        monitor_resource_budget(state_clone_resource).await;
    });

    // Spawn workers in background so dashboard/signal loops run immediately
    let state_clone_spawn = Arc::clone(&state);
    tokio::spawn(async move {
        for t in WORKER_TYPES {
            start_worker(Arc::clone(&state_clone_spawn), t).await;
            time::sleep(Duration::from_millis(STARTUP_STAGGER_MS)).await;
        }
    });

    tokio::select! {
        _ = sigint.recv() => { println!("SIGINT received"); stop_all(Arc::clone(&state)).await; }
        _ = sigterm.recv() => { println!("SIGTERM received"); stop_all(Arc::clone(&state)).await; }
    }

    Ok(())
}
