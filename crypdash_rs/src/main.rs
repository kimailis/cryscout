use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use serde::Deserialize;
use std::fs;
use std::io;
use std::time::{Duration, Instant};

const STATUS_FILE: &str = "service_status.json";

#[derive(Deserialize, Debug, Default)]
struct HubStatus {
    running: bool,
    current_task: String,
    cpu_usage: f64,
    ram_usage: f64,
    last_heartbeat: f64,
    pid: u32,
    logs: Vec<String>,
    worker_count: usize,
}

fn get_service_info() -> HubStatus {
    if let Ok(content) = fs::read_to_string(STATUS_FILE) {
        if let Ok(status) = serde_json::from_str::<HubStatus>(&content) {
            return status;
        }
    }
    HubStatus {
        current_task: "Stopped / Not Responding".to_string(),
        ..Default::default()
    }
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let tick_rate = Duration::from_millis(500);
    let mut last_tick = Instant::now();

    loop {
        let status = get_service_info();

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(3),
                        Constraint::Length(7),
                        Constraint::Min(0),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // Header
            let header_text = format!(" CryScout Dashboard | State: {} | Task: {}", if status.running { "RUNNING" } else { "STOPPED" }, status.current_task);
            let header = Paragraph::new(header_text).block(Block::default().borders(Borders::ALL).title("CryScout"));
            f.render_widget(header, chunks[0]);

            // Stats
            let stats_text = format!(
                "Workers Active: {}\nCPU Usage: {:.1}%\nRAM Usage: {:.1}%\nHub PID: {}",
                status.worker_count, status.cpu_usage, status.ram_usage, status.pid
            );
            let stats = Paragraph::new(stats_text).block(Block::default().borders(Borders::ALL).title("System Info"));
            f.render_widget(stats, chunks[1]);

            // Logs
            let logs_text = status.logs.join("\n");
            let logs = Paragraph::new(logs_text).block(Block::default().borders(Borders::ALL).title("Recent Logs"));
            f.render_widget(logs, chunks[2]);
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    return Ok(());
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}
