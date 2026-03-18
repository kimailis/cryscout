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

const WORKER_TYPES: &[&str] = &["scanner", "analyzer", "striker", "scouter", "fetcher", "neural_scout"];

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

struct HubState {
    workers: HashMap<u32, WorkerInfo>,
    running: bool,
    log_buffer: Vec<String>,
    system: System,
}

impl HubState {
    fn new() -> Self {
        Self {
            workers: HashMap::new(),
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
            let _ = conn.pragma_update(None, "busy_timeout", &5000);
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

async fn handle_worker_stdout(
    state: Arc<RwLock<HubState>>,
    pid: u32,
    worker_type: String,
    mut stdout: tokio::process::ChildStdout,
) {
    let mut reader = BufReader::new(&mut stdout);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let text = line.trim();
                if !text.is_empty() {
                    state.write().await.log(format!("[{}] {}", worker_type, text));
                }
            }
            Err(_) => break,
        }
    }
    state.write().await.log(format!("Worker {} (PID: {}) stream closed", worker_type, pid));
}

async fn start_worker(state: Arc<RwLock<HubState>>, worker_type: &str) -> Option<u32> {
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
    let w_type = worker_type.to_string();

    {
        let mut s = state.write().await;
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
            let _ = conn.pragma_update(None, "busy_timeout", &5000);
            let _ = conn.execute(
                "INSERT OR REPLACE INTO worker_status (worker_id, task, cpu_usage, ram_usage, last_heartbeat)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                params![format!("{}-{}", worker_type, pid), "Initializing...", 0.0, 0.0],
            );
        }
    }
    
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        handle_worker_stdout(state_clone, pid, w_type, stdout).await;
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
            let _ = conn.pragma_update(None, "busy_timeout", &5000);
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
                s.log("Spawning fresh worker fleet...".to_string());
                drop(s);

                for t in WORKER_TYPES {
                    start_worker(Arc::clone(&state), t).await;
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
            update_dashboard_json(Arc::clone(&state_clone_bg)).await;
        }
    });

    tokio::select! {
        _ = sigint.recv() => { println!("SIGINT received"); stop_all(Arc::clone(&state)).await; }
        _ = sigterm.recv() => { println!("SIGTERM received"); stop_all(Arc::clone(&state)).await; }
    }

    Ok(())
}
