#[cfg(not(unix))]
compile_error!("routeloomctl v0.1 currently requires a Unix platform");

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn usage() {
    eprintln!("routeloomctl [--socket PATH] status|diagnostics|autonomy|send <node> <hex>");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut socket = PathBuf::from("/tmp/routeloom.sock");
    let mut remaining = Vec::new();
    // --socket is accepted in any position, not only before the command.
    while let Some(argument) = args.next() {
        if argument == "--socket" {
            socket = PathBuf::from(args.next().ok_or("--socket requires a path")?);
        } else {
            remaining.push(argument);
        }
    }
    let command = match remaining.as_slice() {
        [name] if name == "status" => "STATUS".to_string(),
        [name] if name == "diagnostics" => "DIAGNOSTICS".to_string(),
        [name] if name == "autonomy" => "AUTONOMY".to_string(),
        [name, node, payload] if name == "send" => format!("SEND {node} {payload}"),
        _ => {
            usage();
            return Err("invalid command".into());
        }
    };
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    if response.is_empty() {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "daemon closed connection").into(),
        );
    }
    print!("{response}");
    Ok(())
}
