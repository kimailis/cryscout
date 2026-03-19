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
const MAX_CPU_FOR_SPAWN: f32 = 85.0;
const MAX_RAM_FOR_SPAWN: f64 = 90.0;
const CRASH_LOOP_UPTIME_SECS: f64 = 60.0;
const INITIAL_RESTART_BACKOFF_SECS: u64 = 5;
const MAX_RESTART_BACKOFF_SECS: u64 = 300;
const STARTUP_STAGGER_MS: u64 = 750;

const WORKER_TYPES: &[&str] = &["scanner", "striker", "scouter", "fetcher", "neural_scout", "scorer"];

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
}

struct HubState {
    workers: HashMap<u32, WorkerInfo>,
    restart_policy: HashMap<String, RestartPolicy>,
    running: bool,
    log_buffer: Vec<String>,
    system: System,
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
        _ => worker_type,
    };
    format!("{}-{}", label, pid)
}

impl HubState {
    fn new() -> Self {
        Self {
            workers: HashMap::new(),
            restart_policy: HashMap::new(),
            running: false,
            log_buffer: Vec::new(),
            system: System::new_all(),
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
    loop {
        let (running, wait_secs, cpu, ram) = {
            let mut s = state.write().await;
            s.system.refresh_cpu_usage();
            s.system.refresh_memory();
            let cpu = s.system.global_cpu_info().cpu_usage();
            let ram = (s.system.used_memory() as f64 / s.system.total_memory() as f64) * 100.0;
            let running = s.running;
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
        };

        if !running {
            return false;
        }

        if wait_secs == 0 {
            return true;
        }

        state.write().await.log(format!(
            "Deferring {} start for {}s due to restart/resource budget (CPU {:.1}%, RAM {:.1}%)",
            worker_type,
            wait_secs.min(15),
            cpu,
            ram
        ));
        time::sleep(Duration::from_secs(wait_secs.min(15))).await;
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
        _ => "./target/release/cryscout_worker_rs",
    };
    
    let mut command = Command::new(worker_binary);
    if worker_type != "scouter" && worker_type != "neural_scout" {
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
    let worker_details = get_worker_details().await;
    let mut s = state.write().await;
    s.system.refresh_cpu_usage();
    s.system.refresh_memory();
    
    let last_heartbeat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let status = HubStatus {
        running: s.running,
        current_task: format!("Hub active: {} workers", worker_details.len()),
        cpu_usage: s.system.global_cpu_info().cpu_usage() as f64,
        ram_usage: (s.system.used_memory() as f64 / s.system.total_memory() as f64) * 100.0,
        last_heartbeat,
        last_update: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        pid: std::process::id(),
        logs: s.log_buffer.clone(),
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

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    
    let state_clone_bg = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            check_signals(Arc::clone(&state_clone_bg)).await;
            reap_workers(Arc::clone(&state_clone_bg)).await;
            update_dashboard_json(Arc::clone(&state_clone_bg)).await;
        }
    });

    tokio::select! {
        _ = sigint.recv() => { println!("SIGINT received"); stop_all(Arc::clone(&state)).await; }
        _ = sigterm.recv() => { println!("SIGTERM received"); stop_all(Arc::clone(&state)).await; }
    }

    Ok(())
}
