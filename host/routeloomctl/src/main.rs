#[cfg(not(unix))]
compile_error!("routeloomctl v0.1 currently requires a Unix platform");

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn usage() {
    eprintln!(
        "routeloomctl [--socket PATH] status|diagnostics|autonomy|send <node> <hex>|receive --network <16hex> [--from earliest|latest | --cursor CURSOR] [--limit 1-32]"
    );
}

/// One ASCII request id per invocation (connection correlation only —
/// never operation identity).
fn request_id() -> String {
    format!("ctl-{}", std::process::id())
}

/// Build the API1 `messages.read` request line for the `receive` command.
/// `cursor` characters are validated against the base64url alphabet so the
/// token cannot inject JSON — it arrives as an opaque string, never trusted.
fn receive_request(network: &str, from: &str, cursor: Option<&str>, limit: u64) -> String {
    let position = match cursor {
        Some(cursor) => format!("\"cursor\":\"{cursor}\""),
        None => format!("\"from\":\"{from}\""),
    };
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"messages.read\",\"params\":{{\"network\":\"{network}\",{position},\"limit\":{limit}}}}}",
        request_id(),
    )
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
        [name, rest @ ..] if name == "receive" => receive_command(rest)?,
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

/// `receive --network <16hex> [--from earliest|latest | --cursor CUR]
/// [--limit N]`. Thin client over `messages.read`: prints the daemon's JSON
/// result verbatim. Unlike the legacy `SEND <hex>` verb, the API1 path can
/// express and return empty payloads (`payload_len:0`, `payload_hex:""`).
fn receive_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut from: Option<String> = None;
    let mut cursor: Option<String> = None;
    let mut limit: u64 = 32;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => {
                network = Some(
                    args.next()
                        .ok_or("--network requires a 16-hex id")?
                        .to_string(),
                )
            }
            "--from" => {
                from = Some(
                    args.next()
                        .ok_or("--from requires earliest|latest")?
                        .to_string(),
                )
            }
            "--cursor" => {
                cursor = Some(args.next().ok_or("--cursor requires a token")?.to_string())
            }
            "--limit" => {
                limit = args
                    .next()
                    .ok_or("--limit requires a number")?
                    .parse::<u64>()
                    .map_err(|_| "--limit must be an integer 1-32")?
            }
            other => return Err(format!("unknown receive option: {other}").into()),
        }
    }
    let network = network.ok_or("receive requires --network <16hex>")?;
    if network.len() != 16 || !network.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--network must be a 16-hex id".into());
    }
    if from.is_some() && cursor.is_some() {
        return Err("--from and --cursor are mutually exclusive".into());
    }
    if let Some(from) = &from {
        if from != "earliest" && from != "latest" {
            return Err("--from must be earliest or latest".into());
        }
    }
    if let Some(cursor) = &cursor {
        if cursor.is_empty()
            || cursor.len() > 128
            || !cursor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("--cursor must be a base64url (no padding) token".into());
        }
    }
    if !(1..=32).contains(&limit) {
        return Err("--limit must be an integer 1-32".into());
    }
    let from = from.unwrap_or_else(|| "earliest".to_string());
    Ok(receive_request(
        &network.to_ascii_lowercase(),
        &from,
        cursor.as_deref(),
        limit,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_builds_api1_line() {
        let line = receive_request("0000000000000001", "earliest", None, 32);
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"messages.read\""));
        assert!(line.contains("\"network\":\"0000000000000001\""));
        assert!(line.contains("\"from\":\"earliest\""));
        assert!(line.contains("\"limit\":32"));
        let with_cursor = receive_request("0000000000000001", "earliest", Some("AbC-_123"), 5);
        assert!(with_cursor.contains("\"cursor\":\"AbC-_123\""));
        assert!(!with_cursor.contains("\"from\""));
    }
}
