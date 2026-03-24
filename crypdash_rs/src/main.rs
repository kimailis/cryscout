use anyhow::{Result};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{fs, io, time::{Duration, Instant}};
use regex::Regex;

const DB_PATH: &str = "cryscout.db";
const STATUS_FILE: &str = "service_status.json";
const SIGNAL_FILE: &str = "service_signal.txt";
const HEARTBEAT_FRESHNESS_SECS: f64 = 15.0;

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct WorkerDetail {
    id: String,
    task: String,
    cpu: f64,
    ram: f64,
    last_seen: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
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

#[derive(Default)]
struct Stats {
    total: i64,
    analyzed: i64,
    dormant: i64,
    vulnerabilities: i64,
    keys_recovered: i64,
    attacked: i64,
    success_prob: f64,
    max_individual_prob: f64,
    active_workers: i64,
    scouter_checked: i64,
    scouter_kps: f64,
}

struct PotentialTarget {
    address: String,
    balance: String,
    reason: String,
}

struct RecoveredKey {
    address: String,
    key: String,
    balance: f64,
    method: String,
}

struct AttackReport {
    address: String,
    method: String,
    severity: String,
    details: String,
}

#[derive(PartialEq, Clone, Copy)]
enum AppMode {
    Main,
    Potential,
    Keys,
    Attacks,
    Scout,
}

struct App {
    mode: AppMode,
    status: HubStatus,
    stats: Stats,
    potential_targets: Vec<PotentialTarget>,
    recovered_keys: Vec<RecoveredKey>,
    total_recovered_btc: f64,
    attack_reports: Vec<AttackReport>,
}

impl App {
    fn new() -> Self {
        Self {
            mode: AppMode::Main,
            status: HubStatus::default(),
            stats: Stats::default(),
            potential_targets: Vec::new(),
            recovered_keys: Vec::new(),
            total_recovered_btc: 0.0,
            attack_reports: Vec::new(),
        }
    }

    fn is_pid_alive(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
            return !status.contains("State:\tZ");
        }
        false
    }

    fn is_hub_alive(&self) -> bool {
        if self.is_pid_alive(self.status.pid) {
            return true;
        }

        // Use pgrep -x to find the exact binary name
        let output = std::process::Command::new("pgrep")
            .arg("-x")
            .arg("cryshub_rs")
            .output();
        
        if let Ok(out) = output {
            let pids = String::from_utf8_lossy(&out.stdout);
            for pid_str in pids.lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    // Check /proc/pid/status for State
                    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
                        // If it's a zombie (State: Z), it's not "alive" for our purposes
                        if !status.contains("State:\tZ") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_fresh_status(&self) -> bool {
        if self.status.last_heartbeat <= 0.0 {
            return false;
        }
        let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
        now - self.status.last_heartbeat <= HEARTBEAT_FRESHNESS_SECS
    }

    fn send_signal(&self, sig: &str) -> Result<()> {
        // Overwrite signal file FIRST to ensure hub sees it on startup
        fs::write(SIGNAL_FILE, sig)?;

        if sig == "RESTART" {
            if !self.is_hub_alive() {
                // Determine absolute path to hub
                let current_dir = std::env::current_dir()?;
                let hub_path = current_dir.join("target/release/cryshub_rs");
                
                let _ = std::process::Command::new(&hub_path)
                    .current_dir(&current_dir)
                    .stdout(std::fs::File::create("hub_live.log").unwrap_or_else(|_| std::fs::File::open("/dev/null").unwrap()))
                    .stderr(std::fs::File::create("hub_error.log").unwrap_or_else(|_| std::fs::File::open("/dev/null").unwrap()))
                    .spawn();
                
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        Ok(())
    }

    fn update_data(&mut self) -> Result<()> {
        if let Ok(content) = fs::read_to_string(STATUS_FILE) {
            if let Ok(s) = serde_json::from_str::<HubStatus>(&content) {
                self.status = s;
            }
        }
        
        if !self.is_hub_alive() || !self.has_fresh_status() {
            self.status.last_update = "".to_string();
            self.status.running = false;
            self.status.worker_count = 0;
            self.status.workers_detailed.clear();
        }

        self.stats = self.get_db_stats()?;
        if !self.status.running {
            self.stats.active_workers = 0;
        }
        self.potential_targets = self.get_potential_targets()?;
        let (keys, total_btc) = self.get_recovered_keys()?;
        self.recovered_keys = keys;
        self.total_recovered_btc = total_btc;
        self.attack_reports = self.get_attack_reports()?;
        Ok(())
    }

    fn get_db_stats(&self) -> Result<Stats> {
        let conn = Connection::open(DB_PATH)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        let mut stats = Stats::default();
        stats.total = conn.query_row("SELECT COUNT(*) FROM addresses", [], |r| r.get(0)).unwrap_or(0);
        stats.analyzed = conn.query_row("SELECT COUNT(*) FROM addresses WHERE analyzed = 1", [], |r| r.get(0)).unwrap_or(0);
        stats.dormant = conn.query_row("SELECT COUNT(*) FROM addresses WHERE status = 'Dormant'", [], |r| r.get(0)).unwrap_or(0);
        stats.vulnerabilities = conn.query_row("SELECT COUNT(*) FROM vulnerabilities", [], |r| r.get(0)).unwrap_or(0);
        stats.keys_recovered = conn.query_row("SELECT COUNT(*) FROM recovered_keys", [], |r| r.get(0)).unwrap_or(0);
        stats.attacked = conn.query_row("SELECT COUNT(*) FROM addresses WHERE analyzed = 1", [], |r| r.get(0)).unwrap_or(0);
        stats.active_workers = conn.query_row("SELECT COUNT(*) FROM worker_status WHERE last_heartbeat > datetime('now', '-120 seconds')", [], |r| r.get(0)).unwrap_or(0);
        stats.scouter_checked = conn.query_row("SELECT value_i FROM global_stats WHERE key = 'scouter_checked'", [], |r| r.get(0)).unwrap_or(0);
        
        let kps_str: String = conn.query_row("SELECT task FROM worker_status WHERE worker_id LIKE 'Scouter%' ORDER BY last_heartbeat DESC LIMIT 1", [], |r| r.get(0)).unwrap_or_else(|_| "".to_string());
        if let Some(caps) = Regex::new(r"\((\d+) kps\)")?.captures(&kps_str) {
            stats.scouter_kps = caps.get(1).map_or(0.0, |m| m.as_str().parse().unwrap_or(0.0));
        }
        self.calculate_probabilities(&conn, &mut stats)?;
        Ok(stats)
    }

    fn calculate_probabilities(&self, conn: &Connection, stats: &mut Stats) -> Result<()> {
        let mut addr_probs: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut stmt = conn.prepare("SELECT address, type, details, severity FROM vulnerabilities")?;
        let vulns = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?;
        for vuln in vulns {
            let (addr, v_type, v_details, v_sev) = vuln?;
            let entry = addr_probs.entry(addr.clone()).or_insert(1.0);
            let mut p = 0.00001;
            if v_type.contains("R-Reuse") { p = if v_details.contains("Different Z") { 0.99 } else { 0.005 }; }
            else if v_type.contains("Lattice") || v_type.contains("HNP") { p = 0.95; }
            else if v_type.contains("Fourier") || v_type.contains("Spectral") { p = 0.70; }
            else if v_type.contains("Neural") || v_type.contains("Anomaly") {
                // Extract P(vulnerable) from details like "P(vulnerable)=0.9923 — ..."
                p = if let Some(start) = v_details.find("P(vulnerable)=") {
                    v_details[start + 15..].split(|c: char| !c.is_ascii_digit() && c != '.').next()
                        .and_then(|s| s.parse::<f64>().ok())
                        .map(|score| if score > 0.9 { 0.60 } else if score > 0.7 { 0.40 } else { 0.15 })
                        .unwrap_or(0.40)
                } else { 0.40 };
            }
            else if v_type.contains("Small R") { p = if v_sev == "High" { 0.01 } else { 0.002 }; }
            else if v_type.contains("LSB Bias") { p = if v_sev == "High" { 0.005 } else { 0.001 }; }
            *entry *= 1.0 - p;
        }
        let mut stmt = conn.prepare("SELECT address, vulnerability_score FROM addresses WHERE vulnerability_score > 0")?;
        let scores = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?)))?;
        for score in scores {
            let (addr, val) = score?;
            let entry = addr_probs.entry(addr).or_insert(1.0);
            let p = (val * 0.01).min(0.05); 
            *entry *= 1.0 - p;
        }
        let mut total_fail_prob = 1.0;
        let mut max_indiv = 0.0;
        for (_, fail_p) in addr_probs {
            let success_p = 1.0 - fail_p;
            if success_p > max_indiv { max_indiv = success_p; }
            total_fail_prob *= 1.0 - success_p;
        }
        stats.success_prob = (1.0 - total_fail_prob) * 100.0;
        stats.max_individual_prob = max_indiv * 100.0;
        Ok(())
    }

    fn get_potential_targets(&self) -> Result<Vec<PotentialTarget>> {
        let conn = Connection::open(DB_PATH)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        let mut stmt = conn.prepare("SELECT address, balance, COALESCE(potential_weakness, 'Statistical Bias') FROM addresses WHERE vulnerability_score > 0 ORDER BY rank ASC LIMIT 20")?;
        let rows = stmt.query_map([], |row| Ok(PotentialTarget { address: row.get(0)?, balance: format!("{:.2} BTC", row.get::<_, f64>(1)?), reason: row.get(2)? }))?;
        let mut targets = Vec::new();
        for row in rows { targets.push(row?); }
        Ok(targets)
    }

    fn get_recovered_keys(&self) -> Result<(Vec<RecoveredKey>, f64)> {
        let conn = Connection::open(DB_PATH)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        let mut stmt = conn.prepare("SELECT r.address, r.privkey_hex, r.method, COALESCE(a.balance, 0.0) FROM recovered_keys r LEFT JOIN addresses a ON r.address = a.address")?;
        let rows = stmt.query_map([], |row| Ok(RecoveredKey { address: row.get(0)?, key: row.get(1)?, method: row.get(2)?, balance: row.get(3)? }))?;
        let mut keys = Vec::new();
        let mut total = 0.0;
        for row in rows { let k = row?; total += k.balance; keys.push(k); }
        Ok((keys, total))
    }

    fn get_attack_reports(&self) -> Result<Vec<AttackReport>> {
        let mut reports = Vec::new();
        let conn = Connection::open(DB_PATH)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        let mut stmt = conn.prepare("SELECT address, type, severity, details FROM vulnerabilities ORDER BY found_at DESC LIMIT 50")?;
        let rows = stmt.query_map([], |row| Ok(AttackReport { address: row.get(0)?, method: row.get(1)?, severity: row.get(2)?, details: row.get(3)? }))?;
        for row in rows { reports.push(row?); }
        
        let addr_regex = Regex::new(r"([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})").unwrap();
        let mut last_addr = "Unknown".to_string();
        for log in &self.status.logs {
            let mut current_line_addr = None;
            if let Some(m) = addr_regex.find(log) { 
                last_addr = m.as_str().to_string(); 
                current_line_addr = Some(last_addr.clone());
            }
            
            let lower = log.to_lowercase();
            if lower.contains("fourier") || lower.contains("fft") || lower.contains("bias") || lower.contains("anomaly") || lower.contains("hit") || lower.contains("strike") || lower.contains("relation") || lower.contains("lattice") {
                reports.push(AttackReport {
                    address: current_line_addr.unwrap_or_else(|| last_addr.clone()),
                    method: if lower.contains("fourier") { "Fourier" } else if lower.contains("fft") || lower.contains("spectral") { "Spectral" } else if lower.contains("anomaly") || lower.contains("neural") { "Neural" } else if lower.contains("relation") { "Nonce Rel" } else if lower.contains("lattice") || lower.contains("lll") { "Lattice" } else { "Strike" }.to_string(),
                    details: log.split(']').last().unwrap_or(log).trim().to_string(),
                    severity: if lower.contains("!") || lower.contains("high") || lower.contains("hit") { "High".to_string() } else { "Info".to_string() },
                });
            }
        }
        Ok(reports)
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(f.size());
    let menu = vec![" [M] Dashboard ", " [P] Potential ", " [K] Keys ", " [A] Attacks ", " [S] Scout "];
    let tabs = Tabs::new(menu)
        .block(Block::default().borders(Borders::ALL).title(" CryScout Advanced Fleet Controller "))
        .select(match app.mode { AppMode::Main => 0, AppMode::Potential => 1, AppMode::Keys => 2, AppMode::Attacks => 3, AppMode::Scout => 4 })
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);
    match app.mode {
        AppMode::Main => draw_main_view(f, app, chunks[1]),
        AppMode::Potential => draw_potential_view(f, app, chunks[1]),
        AppMode::Keys => draw_keys_view(f, app, chunks[1]),
        AppMode::Attacks => draw_attacks_view(f, app, chunks[1]),
        AppMode::Scout => draw_scout_view(f, app, chunks[1]),
    }
    let footer_text = " [Q] Quit | [Tab] Cycle | [R] START/RESTART FLEET | [X] STOP HUB/FLEET ";
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)).alignment(Alignment::Center);
    f.render_widget(footer, chunks[2]);
}

fn draw_main_view(f: &mut Frame, app: &App, area: Rect) {
    let vertical_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(70), Constraint::Percentage(30)]).split(area);
    let top_chunks = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(40), Constraint::Percentage(60)]).split(vertical_chunks[0]);

    // System Overview
    let mut status_lines = Vec::new();
    status_lines.push(Line::from(vec![
        Span::raw("Hub Status:         "), 
        if app.status.last_update != "" { Span::styled("ONLINE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)) } 
        else { Span::styled("IDLE/OFFLINE", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)) }
    ]));
    status_lines.push(Line::from(vec![
        Span::raw("Workers Status:     "), 
        if app.status.running { Span::styled("RUNNING", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)) } 
        else { Span::styled("IDLE/PAUSED", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)) }
    ]));
    status_lines.push(Line::from(format!("Last Sync:          {}", app.status.last_update)));
    status_lines.push(Line::from(""));
    status_lines.push(Line::from(format!("Total Tracked:      {}", app.stats.total)));
    status_lines.push(Line::from(format!("Analyzed:           {}", app.stats.analyzed)));
    status_lines.push(Line::from(format!("Dormant Targets:    {}", app.stats.dormant)));
    status_lines.push(Line::from(format!("Keys Recovered:     {}", app.stats.keys_recovered)));
    status_lines.push(Line::from(format!("Active Workers:     {}", app.status.workers_detailed.len())));
    
    let progress = if app.stats.total > 0 { (app.stats.analyzed as f64 / app.stats.total as f64) * 100.0 } else { 0.0 };
    status_lines.push(Line::from(""));
    status_lines.push(Line::from(vec![
        Span::raw("Fleet Progress:     "),
        Span::styled(format!("{:.1}%", progress), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
    ]));
    status_lines.push(Line::from(vec![Span::raw("Fleet Probability:  "), Span::styled(format!("{:.3}%", app.stats.success_prob), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]));
    let status_block = Paragraph::new(status_lines).block(Block::default().borders(Borders::ALL).title(" System Overview "));
    f.render_widget(status_block, top_chunks[0]);

    // Live Worker Fleet
    let header = Row::new(vec!["Worker ID", "Task", "CPU", "RAM"]).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));
    let rows: Vec<Row> = app.status.workers_detailed.iter().map(|w| {
        let task_style = if w.task.to_lowercase().contains("kps") || w.task.to_lowercase().contains("strike") { Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow) } else { Style::default() };
        Row::new(vec![w.id.chars().take(15).collect::<String>(), w.task.clone(), format!("{:.1}%", w.cpu), format!("{:.1}%", w.ram)]).style(task_style)
    }).collect();
    let table = Table::new(rows, [Constraint::Length(16), Constraint::Min(20), Constraint::Length(7), Constraint::Length(7)]).header(header).block(Block::default().borders(Borders::ALL).title(" Live Worker Fleet "));
    f.render_widget(table, top_chunks[1]);

    // Global Logs
    let logs_text: Vec<Line> = app.status.logs.iter().rev().take(10).rev().map(|l| Line::from(Span::raw(l.clone()))).collect();
    let logs = Paragraph::new(logs_text).block(Block::default().borders(Borders::ALL).title(" Recent System Events "));
    f.render_widget(logs, vertical_chunks[1]);
}

fn draw_potential_view(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Address", "Balance", "Reason"]).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));
    let rows: Vec<Row> = app.potential_targets.iter().map(|t| Row::new(vec![t.address.clone(), t.balance.clone(), t.reason.clone()])).collect();
    let table = Table::new(rows, [Constraint::Length(35), Constraint::Length(15), Constraint::Min(20)]).header(header).block(Block::default().borders(Borders::ALL).title(" Potential Targets (High Prob) "));
    f.render_widget(table, area);
}

fn draw_keys_view(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(0), Constraint::Length(3)]).split(area);
    let header = Row::new(vec!["Address", "Private Key", "Balance", "Method"]).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Green));
    let rows: Vec<Row> = app.recovered_keys.iter().map(|k| Row::new(vec![k.address.clone(), k.key.clone(), format!("{:.4} BTC", k.balance), k.method.clone()]).style(Style::default().fg(Color::Green))).collect();
    let table = Table::new(rows, [Constraint::Length(35), Constraint::Length(30), Constraint::Length(15), Constraint::Min(15)]).header(header).block(Block::default().borders(Borders::ALL).title(" RECOVERED KEYS (SUCCESS!) "));
    f.render_widget(table, chunks[0]);
    let summary = format!("TOTAL: {} keys recovered | {:.4} BTC accessible", app.recovered_keys.len(), app.total_recovered_btc);
    let summary_p = Paragraph::new(summary).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Green)).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL));
    f.render_widget(summary_p, chunks[1]);
}

fn draw_attacks_view(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let header = Row::new(vec!["Address", "Method", "Severity", "Details"]).style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Magenta));
    let rows: Vec<Row> = app.attack_reports.iter().map(|r| {
        let style = if r.severity == "High" { Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD) } else { Style::default() };
        Row::new(vec![r.address.clone(), r.method.clone(), r.severity.clone(), r.details.clone()]).style(style)
    }).collect();
    let table = Table::new(rows, [Constraint::Length(35), Constraint::Length(15), Constraint::Length(10), Constraint::Min(40)]).header(header).block(Block::default().borders(Borders::ALL).title(" Advanced Attack Reports (Findings) "));
    f.render_widget(table, chunks[0]);
    let logs_text: Vec<Line> = app.status.logs.iter().rev().take(50).rev().map(|l| Line::from(Span::raw(l.clone()))).collect();
    let logs = Paragraph::new(logs_text).block(Block::default().borders(Borders::ALL).title(" Live Attack Module Output "));
    f.render_widget(logs, chunks[1]);
}

fn draw_scout_view(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(10), Constraint::Min(10)]).split(area);
    let mut scout_lines = Vec::new();
    scout_lines.push(Line::from(vec![Span::raw("Brute-Force Status: "), if app.status.running { Span::styled("ACTIVE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)) } else { Span::styled("PAUSED", Style::default().fg(Color::Red)) }]));
    scout_lines.push(Line::from(format!("Total Phrases Checked: {}", app.stats.scouter_checked)));
    scout_lines.push(Line::from(format!("Current Speed:         {:.0} keys/s", app.stats.scouter_kps)));
    let scouter_task: String = app.status.workers_detailed.iter().find(|w| w.id.to_lowercase().contains("scouter")).map(|w| w.task.clone()).unwrap_or_default();
    let sample_info = if let Some(parts) = scouter_task.split(" | ").nth(1) { parts.to_string() } else { "Waiting for sample...".to_string() };
    scout_lines.push(Line::from(""));
    scout_lines.push(Line::from(vec![Span::styled("LATEST SAMPLE:", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))]));
    if let Some((m, a)) = sample_info.split_once(" -> ") { scout_lines.push(Line::from(format!("  Mnemonic: {}", m))); scout_lines.push(Line::from(format!("  Address:  {}", a))); }
    else { scout_lines.push(Line::from(format!("  {}", sample_info))); }
    let status_block = Paragraph::new(scout_lines).block(Block::default().borders(Borders::ALL).title(" WalletScout Real-Time Pipeline "));
    f.render_widget(status_block, chunks[0]);
    
    let scout_logs: Vec<Line> = app.status.logs.iter().filter(|l| {
        let lower = l.to_lowercase();
        lower.contains("scouter") || lower.contains("hit") || lower.contains("scouting") || lower.contains("mnemonic") || lower.contains("combination")
    }).cloned().collect::<Vec<_>>().into_iter().rev().take(50).rev().map(|l| Line::from(Span::raw(l))).collect();
    let logs = Paragraph::new(scout_logs).block(Block::default().borders(Borders::ALL).title(" Scouting Event Log "));
    f.render_widget(logs, chunks[1]);
}

fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let tick_rate = Duration::from_millis(1000);
    let mut last_tick = Instant::now();
    loop {
        // Reap any zombie children (like exited Hub)
        unsafe {
            let mut status = 0;
            while libc::waitpid(-1, &mut status, libc::WNOHANG) > 0 {}
        }

        if last_tick.elapsed() >= tick_rate { let _ = app.update_data(); last_tick = Instant::now(); }
        terminal.draw(|f| ui(f, &app))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('m') => app.mode = AppMode::Main,
                        KeyCode::Char('p') => app.mode = AppMode::Potential,
                        KeyCode::Char('k') => app.mode = AppMode::Keys,
                        KeyCode::Char('a') => app.mode = AppMode::Attacks,
                        KeyCode::Char('s') => app.mode = AppMode::Scout,
                        KeyCode::Char('x') => { let _ = app.send_signal("STOP"); },
                        KeyCode::Char('r') => { let _ = app.send_signal("RESTART"); },
                        KeyCode::Tab => { app.mode = match app.mode { AppMode::Main => AppMode::Potential, AppMode::Potential => AppMode::Keys, AppMode::Keys => AppMode::Attacks, AppMode::Attacks => AppMode::Scout, AppMode::Scout => AppMode::Main }; }
                        _ => {}
                    }
                }
            }
        }
    }
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
