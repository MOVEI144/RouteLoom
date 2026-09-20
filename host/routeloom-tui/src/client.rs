//! Unix-socket client for the routeloom-host daemon. Line-oriented
//! request/response on one persistent connection; on failure the client
//! drops back to disconnected and retries with exponential backoff. All
//! timing is injected (`now_ms`) so reconnect behaviour is testable without
//! sleeping.

use crate::model::{Conn, State};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Commands polled every refresh, in order. Same verbs routeloomctl uses
/// plus the observation surface added for the TUI.
pub const POLL_COMMANDS: [&str; 7] = [
    "STATUS",
    "ADAPTER",
    "NODES",
    "DELIVERIES",
    "EVENTS",
    "AUTHORITY",
    "AUTONOMY",
];

const BACKOFF_MIN_MS: u64 = 250;
const BACKOFF_MAX_MS: u64 = 5_000;
const IO_TIMEOUT: Duration = Duration::from_millis(500);

struct Pipe {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

pub struct DaemonClient {
    socket: PathBuf,
    pipe: Option<Pipe>,
    attempts: u32,
    next_retry_ms: u64,
}

impl DaemonClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            pipe: None,
            attempts: 0,
            next_retry_ms: 0,
        }
    }

    /// Pure backoff schedule: min * 2^attempt, capped at max.
    pub fn backoff_ms(attempt: u32) -> u64 {
        BACKOFF_MIN_MS
            .saturating_mul(1_u64 << attempt.min(10))
            .min(BACKOFF_MAX_MS)
    }

    pub fn is_connected(&self) -> bool {
        self.pipe.is_some()
    }

    /// Drive one refresh cycle. Connects when due, then issues every
    /// POLL_COMMAND and applies the JSON line to `state`. Never blocks beyond
    /// IO_TIMEOUT per command; any failure returns to disconnected state.
    pub fn tick(&mut self, state: &mut State, now_ms: u64) {
        if self.pipe.is_none() {
            if now_ms < self.next_retry_ms {
                return; // still backing off
            }
            match self.connect() {
                Ok(pipe) => {
                    self.pipe = Some(pipe);
                    self.attempts = 0;
                    state.conn = Conn::Connected;
                }
                Err(error) => {
                    self.attempts = self.attempts.saturating_add(1);
                    self.next_retry_ms = now_ms + Self::backoff_ms(self.attempts);
                    state.conn = Conn::Disconnected {
                        since_ms: now_ms,
                        attempts: self.attempts,
                        next_retry_ms: self.next_retry_ms,
                        error: Some(error.to_string()),
                    };
                    return;
                }
            }
        }

        // Poll every command on the existing connection.
        let mut failed: Option<String> = None;
        if let Some(pipe) = self.pipe.as_mut() {
            for command in POLL_COMMANDS {
                let result = pipe
                    .writer
                    .write_all(command.as_bytes())
                    .and_then(|()| pipe.writer.write_all(b"\n"))
                    .and_then(|()| pipe.writer.flush())
                    .and_then(|()| {
                        let mut line = String::new();
                        pipe.reader.read_line(&mut line).map(|_| line)
                    });
                match result {
                    Ok(line) if !line.is_empty() => {
                        if state.apply(command, line.trim_end()).is_err() {
                            state.poll_failures += 1;
                        }
                    }
                    Ok(_) => {
                        failed = Some("daemon closed connection".to_string());
                        break;
                    }
                    Err(error) => {
                        failed = Some(error.to_string());
                        break;
                    }
                }
            }
        }
        match failed {
            None => state.last_refresh_ms = Some(now_ms),
            Some(error) => {
                self.pipe = None;
                // A mid-poll drop is still a failed attempt: keep backing off
                // instead of resetting to the minimum delay every cycle.
                self.attempts = self.attempts.saturating_add(1);
                self.next_retry_ms = now_ms + Self::backoff_ms(self.attempts);
                state.conn = Conn::Disconnected {
                    since_ms: now_ms,
                    attempts: self.attempts,
                    next_retry_ms: self.next_retry_ms,
                    error: Some(error),
                };
            }
        }
    }

    fn connect(&self) -> std::io::Result<Pipe> {
        let writer = UnixStream::connect(&self.socket)?;
        writer.set_read_timeout(Some(IO_TIMEOUT))?;
        writer.set_write_timeout(Some(IO_TIMEOUT))?;
        let reader = BufReader::new(writer.try_clone()?);
        Ok(Pipe { reader, writer })
    }
}
