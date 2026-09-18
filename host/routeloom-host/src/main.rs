#[cfg(not(unix))]
compile_error!("routeloom-host v0.1 currently requires a Unix platform");

use routeloom_protocol::{encode_frame, Frame, FrameKind, StreamDecoder};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct State {
    device: Option<PathBuf>,
    connected: AtomicBool,
    rx_frames: AtomicU64,
    tx_frames: AtomicU64,
    protocol_errors: AtomicU64,
    last_error: Mutex<Option<String>>,
}

fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

fn status_json(state: &State) -> String {
    let error = state
        .last_error
        .lock()
        .expect("last_error poisoned")
        .clone();
    format!(
        "{{\"connected\":{},\"device\":{},\"rx_frames\":{},\"tx_frames\":{},\"protocol_errors\":{},\"last_error\":{}}}",
        state.connected.load(Ordering::Relaxed),
        state.device.as_ref().map_or_else(|| "null".to_string(), |path| format!("\"{}\"", json_escape(&path.display().to_string()))),
        state.rx_frames.load(Ordering::Relaxed),
        state.tx_frames.load(Ordering::Relaxed),
        state.protocol_errors.load(Ordering::Relaxed),
        error.map_or_else(|| "null".to_string(), |value| format!("\"{}\"", json_escape(&value))),
    )
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex payload must have even length".into());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid hex")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid hex".to_string())
        })
        .collect()
}

fn adapter_thread(
    device: PathBuf,
    state: Arc<State>,
    outbound: mpsc::Receiver<Frame>,
) -> io::Result<()> {
    let mut reader = OpenOptions::new().read(true).write(true).open(&device)?;
    let mut writer = reader.try_clone()?;
    state.connected.store(true, Ordering::Relaxed);

    let writer_state = Arc::clone(&state);
    thread::spawn(move || {
        while let Ok(frame) = outbound.recv() {
            let result = encode_frame(&frame)
                .map_err(io::Error::other)
                .and_then(|encoded| writer.write_all(&encoded).and_then(|()| writer.flush()));
            match result {
                Ok(()) => {
                    writer_state.tx_frames.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    writer_state.connected.store(false, Ordering::Relaxed);
                    *writer_state
                        .last_error
                        .lock()
                        .expect("last_error poisoned") = Some(error.to_string());
                    break;
                }
            }
        }
    });

    let mut decoder = StreamDecoder::default();
    let mut buffer = [0_u8; 512];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "adapter disconnected",
                ))
            }
            Ok(count) => {
                for result in decoder.push(&buffer[..count]) {
                    match result {
                        Ok(_frame) => {
                            state.rx_frames.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            state.protocol_errors.fetch_add(1, Ordering::Relaxed);
                            *state.last_error.lock().expect("last_error poisoned") =
                                Some(error.to_string());
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn serve_client(
    stream: UnixStream,
    state: Arc<State>,
    outbound: mpsc::Sender<Frame>,
    session: u64,
    next_request: Arc<AtomicU64>,
) -> io::Result<()> {
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let response = match fields[0].to_ascii_uppercase().as_str() {
            "STATUS" | "DIAGNOSTICS" => status_json(&state),
            "SEND" if fields.len() == 3 => {
                let destination = fields[1].parse::<u64>();
                let payload = parse_hex(fields[2]);
                match (destination, payload) {
                    (Ok(destination), Ok(payload)) if payload.len() <= 128 => {
                        let mut body = destination.to_be_bytes().to_vec();
                        body.extend_from_slice(&payload);
                        let request = next_request.fetch_add(1, Ordering::Relaxed);
                        match outbound.send(Frame {
                            kind: FrameKind::DataToMesh,
                            flags: 0,
                            session,
                            request,
                            body,
                        }) {
                            Ok(()) => format!("{{\"accepted\":true,\"request\":{request}}}"),
                            Err(_) => {
                                "{\"accepted\":false,\"error\":\"adapter unavailable\"}".into()
                            }
                        }
                    }
                    (Ok(_), Ok(_)) => {
                        "{\"accepted\":false,\"error\":\"payload exceeds 128 bytes\"}".into()
                    }
                    _ => "{\"accepted\":false,\"error\":\"invalid SEND syntax\"}".into(),
                }
            }
            "QUIT" => return Ok(()),
            _ => "{\"error\":\"commands: STATUS, DIAGNOSTICS, SEND <node> <hex>, QUIT\"}".into(),
        };
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
}

fn parse_args() -> Result<(PathBuf, Option<PathBuf>), String> {
    let mut socket = PathBuf::from("/tmp/routeloom.sock");
    let mut device = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => socket = PathBuf::from(args.next().ok_or("--socket requires a path")?),
            "--device" => {
                device = Some(PathBuf::from(
                    args.next().ok_or("--device requires a path")?,
                ))
            }
            "--help" | "-h" => {
                println!("routeloom-host [--socket PATH] [--device TTY]");
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((socket, device))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (socket_path, device) = parse_args().map_err(io::Error::other)?;
    if Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let state = Arc::new(State {
        device: device.clone(),
        ..State::default()
    });
    let (outbound_tx, outbound_rx) = mpsc::channel();
    if let Some(device_path) = device {
        let adapter_state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = adapter_thread(device_path, Arc::clone(&adapter_state), outbound_rx)
            {
                adapter_state.connected.store(false, Ordering::Relaxed);
                *adapter_state
                    .last_error
                    .lock()
                    .expect("last_error poisoned") = Some(error.to_string());
            }
        });
    }
    let listener = UnixListener::bind(&socket_path)?;
    let session =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 ^ u64::from(process::id());
    let next_request = Arc::new(AtomicU64::new(1));
    println!("RouteLoom host listening on {}", socket_path.display());
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let client_state = Arc::clone(&state);
                let client_outbound = outbound_tx.clone();
                let client_requests = Arc::clone(&next_request);
                thread::spawn(move || {
                    let _ = serve_client(
                        stream,
                        client_state,
                        client_outbound,
                        session,
                        client_requests,
                    );
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}
