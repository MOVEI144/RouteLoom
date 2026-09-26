#[cfg(not(unix))]
compile_error!("routeloom-tui v0.1 currently requires a Unix platform");

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute, queue,
    style::Print,
    terminal::{self, ClearType},
};
use routeloom_tui::client::DaemonClient;
use routeloom_tui::model::State;
use routeloom_tui::render::{render, Tab};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Refresh interval in milliseconds: a present value must be a positive
/// integer — `--interval 0` would busy-poll the daemon (a review finding),
/// so it is rejected instead of spinning.
fn parse_interval_ms(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|ms| *ms >= 1)
}

fn parse_args() -> (PathBuf, u64) {
    let mut socket = PathBuf::from("/tmp/routeloom.sock");
    let mut interval = 500_u64;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => {
                if let Some(path) = args.next() {
                    socket = PathBuf::from(path);
                }
            }
            "--interval" => {
                if let Some(value) = args.next() {
                    match parse_interval_ms(&value) {
                        Some(ms) => interval = ms,
                        None => {
                            eprintln!("--interval must be a positive integer (milliseconds)");
                            process::exit(2);
                        }
                    }
                }
            }
            "--help" | "-h" => {
                println!("routeloom-tui [--socket PATH] [--interval MS]");
                process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(2);
            }
        }
    }
    (socket, interval)
}

fn draw(stdout: &mut impl Write, frame: &str, height: u16) -> io::Result<()> {
    queue!(stdout, terminal::Clear(ClearType::All))?;
    for (row, line) in frame.lines().enumerate() {
        if row >= usize::from(height) {
            break;
        }
        queue!(stdout, cursor::MoveTo(0, row as u16), Print(line))?;
    }
    stdout.flush()
}

fn run(socket: PathBuf, interval_ms: u64) -> io::Result<()> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, terminal::EnterAlternateScreen)?;

    let result = run_inner(&mut stdout, socket, interval_ms);

    // Always restore the terminal, even on error.
    let _ = execute!(stdout, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
    result
}

fn run_inner(stdout: &mut impl Write, socket: PathBuf, interval_ms: u64) -> io::Result<()> {
    let mut state = State::new(socket.display().to_string());
    let mut client = DaemonClient::new(socket);
    let mut tab = Tab::Overview;
    let started = Instant::now();

    loop {
        let now = now_ms();
        // Backoff is elapsed time; wall time is retained for display only.
        client.tick(&mut state, now, started.elapsed().as_millis() as u64);
        let (width, height) = terminal::size()?;
        let frame = render(&state, tab, usize::from(width), usize::from(height), now);
        draw(stdout, &frame, height)?;

        // Input budget: the remainder of the refresh interval. Events are
        // drained fully so bursts of keys never lag.
        let deadline = std::time::Instant::now() + Duration::from_millis(interval_ms);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || !event::poll(remaining)? {
                break;
            }
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => tab = tab.next(),
                    KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => tab = tab.prev(),
                    KeyCode::Char(digit @ '1'..='9') => {
                        tab = Tab::from_index(usize::from(digit as u8 - b'1'))
                    }
                    _ => {}
                },
                Event::Resize(_, _) => break, // redraw immediately
                _ => {}
            }
        }
    }
}

fn main() -> io::Result<()> {
    let (socket, interval) = parse_args();
    run(socket, interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_rejects_zero_and_garbage() {
        // A zero interval used to be accepted and busy-poll the daemon.
        assert_eq!(parse_interval_ms("0"), None);
        assert_eq!(parse_interval_ms("-5"), None);
        assert_eq!(parse_interval_ms("fast"), None);
        assert_eq!(parse_interval_ms(""), None);
        assert_eq!(parse_interval_ms("1"), Some(1));
        assert_eq!(parse_interval_ms("500"), Some(500));
    }
}
