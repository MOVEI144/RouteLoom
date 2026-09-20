//! Daemon restart/reconnect test: a fake daemon serves the socket protocol
//! over a temp Unix socket; the TUI client must survive the daemon going
//! away, back off, and reconnect when it returns — no panic, no hang.

use routeloom_tui::client::DaemonClient;
use routeloom_tui::model::{Conn, State};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn response_for(command: &str, marker: &str) -> String {
    match command {
        "STATUS" | "DIAGNOSTICS" => {
            "{\"connected\":true,\"device\":\"/dev/fake0\",\"rx_frames\":1,\"tx_frames\":0,\"protocol_errors\":0,\"last_error\":null}".to_string()
        }
        "ADAPTER" => {
            "{\"device\":\"/dev/fake0\",\"connected\":true,\"session\":{\"authenticated\":false,\"id\":null,\"node\":null,\"boot\":null,\"network\":null,\"capability\":null,\"version\":null},\"credit\":{\"observed\":false,\"grant_frames\":0,\"grant_bytes\":0},\"rx_frames\":1,\"tx_frames\":0,\"tx_bytes\":0,\"protocol_errors\":0,\"last_error\":null}".to_string()
        }
        "NODES" => {
            format!("{{\"nodes\":[{{\"id\":{marker},\"role\":\"adapter\",\"seen_ms\":1,\"membership\":\"unknown\",\"reachability\":\"unknown\",\"rssi_dbm\":null,\"lr250\":\"unknown\",\"hop_count\":null}}]}}")
        }
        "DELIVERIES" => "{\"deliveries\":[]}".to_string(),
        "EVENTS" => {
            "{\"events\":[{\"seq\":0,\"ms\":1,\"kind\":\"adapter\",\"state\":\"connected\"}],\"dropped\":0,\"next_seq\":1}".to_string()
        }
        "AUTHORITY" => {
            "{\"state\":\"unknown\",\"source\":null,\"network\":null,\"detail\":\"fake\"}"
                .to_string()
        }
        _ => "{\"error\":\"unknown command\"}".to_string(),
    }
}

struct FakeDaemon {
    stop: mpsc::Sender<()>,
    join: thread::JoinHandle<()>,
}

/// Serve the line protocol until told to stop. `marker` distinguishes the
/// restarted daemon's NODES payload.
fn spawn_fake_daemon(socket: &PathBuf, marker: &str) -> FakeDaemon {
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).expect("bind fake daemon");
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let marker = marker.to_string();
    let join = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let mut clients: Vec<BufReader<UnixStream>> = Vec::new();
        loop {
            if stop_rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true).expect("nonblocking client");
                    clients.push(BufReader::new(stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
            let mut line = String::new();
            for client in &mut clients {
                line.clear();
                match client.read_line(&mut line) {
                    Ok(0) => {}
                    Ok(_) => {
                        let command = line.split_whitespace().next().unwrap_or("");
                        let response = response_for(command, &marker);
                        let stream = client.get_mut();
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
    });
    FakeDaemon {
        stop: stop_tx,
        join,
    }
}

fn temp_socket(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "routeloom-tui-test-{name}-{}.sock",
        std::process::id()
    ))
}

#[test]
fn daemon_restart_reconnects() {
    let socket = temp_socket("reconnect");
    let mut state = State::new(socket.display().to_string());
    let mut client = DaemonClient::new(socket.clone());

    // No daemon yet: connect attempt fails and backs off.
    client.tick(&mut state, 0);
    assert!(!client.is_connected());
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 1, .. }));

    // Still inside the backoff window: no new attempt.
    client.tick(&mut state, 100);
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 1, .. }));

    // Daemon comes up; past the backoff window the client connects.
    let daemon1 = spawn_fake_daemon(&socket, "42");
    client.tick(&mut state, 1_000);
    assert!(client.is_connected());
    assert_eq!(state.conn, Conn::Connected);
    assert_eq!(state.nodes.len(), 1);
    assert_eq!(state.nodes[0].id, 42);
    assert!(!state.events.is_empty());

    // Kill the daemon: the next poll must fail, mark disconnected, no panic.
    let _ = daemon1.stop.send(());
    daemon1.join.join().expect("daemon1 joins");
    // The socket file is gone only after unlink; remove it to be sure the
    // old listener cannot be re-accepted.
    let _ = std::fs::remove_file(&socket);
    client.tick(&mut state, 2_000);
    assert!(!client.is_connected());
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 1, .. }));

    // Backoff: several ticks below the retry time change nothing.
    client.tick(&mut state, 2_100);
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 1, .. }));
    client.tick(&mut state, 2_300);
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 1, .. }));
    // Past the retry deadline a new connect attempt is made and fails.
    client.tick(&mut state, 2_600);
    assert!(matches!(state.conn, Conn::Disconnected { attempts: 2, .. }));

    // Restarted daemon (different node marker). Client reconnects once the
    // backoff expires and refreshes the model — no panic, no stale conn.
    let daemon2 = spawn_fake_daemon(&socket, "77");
    client.tick(&mut state, 4_000);
    assert!(client.is_connected());
    assert_eq!(state.conn, Conn::Connected);
    assert_eq!(state.nodes[0].id, 77);

    let _ = daemon2.stop.send(());
    daemon2.join.join().expect("daemon2 joins");
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn backoff_schedule_is_bounded() {
    assert_eq!(DaemonClient::backoff_ms(0), 250);
    assert_eq!(DaemonClient::backoff_ms(1), 500);
    assert_eq!(DaemonClient::backoff_ms(5), 5_000);
    assert_eq!(DaemonClient::backoff_ms(40), 5_000);
}
