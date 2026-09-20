#[cfg(not(unix))]
compile_error!("routeloomctl v0.1 currently requires a Unix platform");

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn usage() {
    eprintln!(
        "routeloomctl [--socket PATH] status|diagnostics|autonomy|send <node> <hex>|receive --network <16hex> [--from earliest|latest | --cursor CURSOR] [--limit 1-32]|open-epoch --network <16hex>|submit --network <16hex> --epoch <16hex> --to <16hex> --payload <hex> [--key <32hex>] [--gateway] [--ttl-ms 1-30000] [--delivery BEST_EFFORT|RELIABLE] [--storage RAM_ONLY|HOST_DURABLE] [--hop-limit 1-10]|operation-get --id <opid>|operation-get-by-key --network <16hex> --epoch <16hex> --key <32hex>"
    );
}

/// One ASCII request id per invocation (connection correlation only —
/// never operation identity).
fn request_id() -> String {
    format!("ctl-{}", std::process::id())
}

/// Build the API1 `operations.open_epoch` request line.
fn open_epoch_request(network: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"operations.open_epoch\",\"params\":{{\"network\":\"{network}\"}}}}",
        request_id(),
    )
}

/// Parameters for one API1 `messages.submit` request line. All strings are
/// validated (and hex lowercased) by `submit_command` before reaching here.
struct SubmitParams<'a> {
    network: &'a str,
    epoch: &'a str,
    key: &'a str,
    dest_kind: &'a str,
    dest: &'a str,
    payload_hex: &'a str,
    payload_len: usize,
    delivery: &'a str,
    ttl_ms: u64,
    storage: &'a str,
    hop_limit: u64,
}

/// Build the API1 `messages.submit` request line for the `submit` command.
fn submit_request(p: &SubmitParams<'_>) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"{}\",\"admission_epoch\":\"{}\",\"key\":\"{}\",\"destination\":{{\"kind\":\"{}\",\"id\":\"{}\"}},\"payload_hex\":\"{}\",\"payload_len\":{},\"options\":{{\"delivery\":\"{}\",\"ttl_ms\":{},\"storage\":\"{}\",\"hop_limit\":{}}}}}}}",
        request_id(),
        p.network,
        p.epoch,
        p.key,
        p.dest_kind,
        p.dest,
        p.payload_hex,
        p.payload_len,
        p.delivery,
        p.ttl_ms,
        p.storage,
        p.hop_limit,
    )
}

/// Build the API1 `operations.get` / `operations.get_by_key` request lines.
fn operation_get_request(id: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}",
        request_id(),
    )
}

fn operation_get_by_key_request(network: &str, epoch: &str, key: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"operations.get_by_key\",\"params\":{{\"network\":\"{network}\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\"}}}}",
        request_id(),
    )
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
        // Legacy SEND is kept byte-compatible in explicit legacy mode: a
        // fresh daemon-side key per call, no stable re-query, and never
        // auto-converted into the new API (03-send-api.md §2, 08 §4).
        [name, node, payload] if name == "send" => format!("SEND {node} {payload}"),
        [name, rest @ ..] if name == "receive" => receive_command(rest)?,
        [name, rest @ ..] if name == "open-epoch" => open_epoch_command(rest)?,
        [name, rest @ ..] if name == "submit" => submit_command(rest)?,
        [name, rest @ ..] if name == "operation-get" => operation_get_command(rest)?,
        [name, rest @ ..] if name == "operation-get-by-key" => operation_get_by_key_command(rest)?,
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

fn is_hex(text: &str, chars: usize) -> bool {
    text.len() == chars && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `open-epoch --network <16hex>`. Thin client over `operations.open_epoch`:
/// prints the daemon's JSON result verbatim.
fn open_epoch_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
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
            other => return Err(format!("unknown open-epoch option: {other}").into()),
        }
    }
    let network = network.ok_or("open-epoch requires --network <16hex>")?;
    if !is_hex(&network, 16) {
        return Err("--network must be a 16-hex id".into());
    }
    Ok(open_epoch_request(&network.to_ascii_lowercase()))
}

/// `submit --network <16hex> --epoch <16hex> --to <16hex> --payload <hex>
/// [--key <32hex>] [--gateway] [--ttl-ms N] [--delivery D] [--storage S]
/// [--hop-limit N]`. Thin client over `messages.submit`: prints the
/// daemon's JSON result verbatim. Without `--key` a fresh 128-bit key is
/// generated and reported on stderr for later re-query (a simple CLI may
/// generate keys; a library must never change the caller's).
fn submit_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut epoch: Option<String> = None;
    let mut key: Option<String> = None;
    let mut to: Option<String> = None;
    let mut gateway = false;
    let mut payload: Option<String> = None;
    let mut ttl_ms: u64 = 5000;
    let mut delivery = "RELIABLE".to_string();
    // TX-I1 honesty: the daemon has no durable store yet, so the CLI
    // defaults to RAM_ONLY (HOST_DURABLE is passed through and refused).
    let mut storage = "RAM_ONLY".to_string();
    let mut hop_limit: u64 = 10;
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
            "--epoch" => {
                epoch = Some(
                    args.next()
                        .ok_or("--epoch requires a 16-hex id")?
                        .to_string(),
                )
            }
            "--key" => key = Some(args.next().ok_or("--key requires a 32-hex id")?.to_string()),
            "--to" => to = Some(args.next().ok_or("--to requires a 16-hex id")?.to_string()),
            "--gateway" => gateway = true,
            "--payload" => payload = Some(args.next().ok_or("--payload requires hex")?.to_string()),
            "--ttl-ms" => {
                ttl_ms = args
                    .next()
                    .ok_or("--ttl-ms requires a number")?
                    .parse::<u64>()
                    .map_err(|_| "--ttl-ms must be an integer 1-30000")?
            }
            "--delivery" => {
                delivery = args
                    .next()
                    .ok_or("--delivery requires BEST_EFFORT|RELIABLE|APPLIED")?
                    .to_string()
            }
            "--storage" => {
                storage = args
                    .next()
                    .ok_or("--storage requires RAM_ONLY|HOST_DURABLE")?
                    .to_string()
            }
            "--hop-limit" => {
                hop_limit = args
                    .next()
                    .ok_or("--hop-limit requires a number")?
                    .parse::<u64>()
                    .map_err(|_| "--hop-limit must be an integer 1-10")?
            }
            other => return Err(format!("unknown submit option: {other}").into()),
        }
    }
    let network = network.ok_or("submit requires --network <16hex>")?;
    let epoch = epoch.ok_or("submit requires --epoch <16hex> (see open-epoch)")?;
    let to = to.ok_or("submit requires --to <16hex>")?;
    let payload = payload.ok_or("submit requires --payload <hex>")?;
    if !is_hex(&network, 16) {
        return Err("--network must be a 16-hex id".into());
    }
    if !is_hex(&epoch, 16) {
        return Err("--epoch must be a 16-hex id".into());
    }
    if !is_hex(&to, 16) {
        return Err("--to must be a 16-hex id".into());
    }
    if payload.len() % 2 != 0 || !payload.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--payload must be even-length hex".into());
    }
    if payload.len() > 256 {
        return Err("--payload exceeds 128 bytes".into());
    }
    if !matches!(delivery.as_str(), "BEST_EFFORT" | "RELIABLE" | "APPLIED") {
        return Err("--delivery must be BEST_EFFORT|RELIABLE|APPLIED".into());
    }
    if !matches!(storage.as_str(), "RAM_ONLY" | "HOST_DURABLE") {
        return Err("--storage must be RAM_ONLY|HOST_DURABLE".into());
    }
    if !(1..=30000).contains(&ttl_ms) {
        return Err("--ttl-ms must be an integer 1-30000".into());
    }
    if !(1..=10).contains(&hop_limit) {
        return Err("--hop-limit must be an integer 1-10".into());
    }
    let key = match key {
        Some(key) => {
            if !is_hex(&key, 32) {
                return Err("--key must be a 32-hex id".into());
            }
            key.to_ascii_lowercase()
        }
        None => {
            let generated = generate_key();
            eprintln!("generated key: {generated}");
            generated
        }
    };
    let payload_len = payload.len() / 2;
    let payload_hex = payload.to_ascii_lowercase();
    Ok(submit_request(&SubmitParams {
        network: &network.to_ascii_lowercase(),
        epoch: &epoch.to_ascii_lowercase(),
        key: &key,
        dest_kind: if gateway { "gateway" } else { "node" },
        dest: &to.to_ascii_lowercase(),
        payload_hex: &payload_hex,
        payload_len,
        delivery: &delivery,
        ttl_ms,
        storage: &storage,
        hop_limit,
    }))
}

/// Fresh 128-bit caller key from /dev/urandom (time^pid fallback).
fn generate_key() -> String {
    use std::io::Read;
    let mut bytes = [0_u8; 16];
    let random = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok();
    if !random {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            ^ u128::from(std::process::id());
        bytes = (seed ^ seed.rotate_left(64)).to_be_bytes();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

/// `operation-get --id <opid>` and `operation-get-by-key --network/--epoch/
/// --key`. Thin clients over the query methods.
fn operation_get_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut id: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => {
                id = Some(
                    args.next()
                        .ok_or("--id requires an operation id")?
                        .to_string(),
                )
            }
            other => return Err(format!("unknown operation-get option: {other}").into()),
        }
    }
    let id = id.ok_or("operation-get requires --id <operation-id>")?;
    let well_formed = id
        .split_once(':')
        .is_some_and(|(lineage, seq)| is_hex(lineage, 32) && is_hex(seq, 16));
    if !well_formed {
        return Err("--id must be <32-hex lineage>:<16-hex sequence>".into());
    }
    Ok(operation_get_request(&id.to_ascii_lowercase()))
}

fn operation_get_by_key_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut epoch: Option<String> = None;
    let mut key: Option<String> = None;
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
            "--epoch" => {
                epoch = Some(
                    args.next()
                        .ok_or("--epoch requires a 16-hex id")?
                        .to_string(),
                )
            }
            "--key" => key = Some(args.next().ok_or("--key requires a 32-hex id")?.to_string()),
            other => return Err(format!("unknown operation-get-by-key option: {other}").into()),
        }
    }
    let network = network.ok_or("operation-get-by-key requires --network <16hex>")?;
    let epoch = epoch.ok_or("operation-get-by-key requires --epoch <16hex>")?;
    let key = key.ok_or("operation-get-by-key requires --key <32hex>")?;
    if !is_hex(&network, 16) {
        return Err("--network must be a 16-hex id".into());
    }
    if !is_hex(&epoch, 16) {
        return Err("--epoch must be a 16-hex id".into());
    }
    if !is_hex(&key, 32) {
        return Err("--key must be a 32-hex id".into());
    }
    Ok(operation_get_by_key_request(
        &network.to_ascii_lowercase(),
        &epoch.to_ascii_lowercase(),
        &key.to_ascii_lowercase(),
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

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn open_epoch_builds_api1_line() {
        let line = open_epoch_command(&args(&["--network", "0000000000000001"])).unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(
            line.contains("\"method\":\"operations.open_epoch\""),
            "{line}"
        );
        assert!(line.contains("\"network\":\"0000000000000001\""), "{line}");
        assert!(open_epoch_command(&args(&[])).is_err());
        assert!(open_epoch_command(&args(&["--network", "zz"])).is_err());
        assert!(open_epoch_command(&args(&["--network", "0000000000000001", "--x", "1"])).is_err());
    }

    #[test]
    fn submit_builds_api1_line() {
        let line = submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--key",
            "00112233445566778899AABBCCDDEEFF",
            "--to",
            "0000000000000003",
            "--payload",
            "00FF80",
            "--ttl-ms",
            "6000",
        ]))
        .unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"messages.submit\""), "{line}");
        assert!(line.contains("\"network\":\"0000000000000001\""), "{line}");
        assert!(
            line.contains("\"admission_epoch\":\"0000000000000001\""),
            "{line}"
        );
        assert!(
            line.contains("\"key\":\"00112233445566778899aabbccddeeff\""),
            "{line}"
        );
        assert!(line.contains("\"kind\":\"node\""), "{line}");
        assert!(line.contains("\"id\":\"0000000000000003\""), "{line}");
        assert!(line.contains("\"payload_hex\":\"00ff80\""), "{line}");
        assert!(line.contains("\"payload_len\":3"), "{line}");
        assert!(line.contains("\"delivery\":\"RELIABLE\""), "{line}");
        assert!(line.contains("\"ttl_ms\":6000"), "{line}");
        assert!(line.contains("\"storage\":\"RAM_ONLY\""), "{line}");
        assert!(line.contains("\"hop_limit\":10"), "{line}");
        // Empty payload is explicit, gateway kind is expressible.
        let empty = submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--key",
            "00112233445566778899aabbccddeeff",
            "--to",
            "0000000000000003",
            "--payload",
            "",
            "--gateway",
        ]))
        .unwrap();
        assert!(empty.contains("\"payload_hex\":\"\""), "{empty}");
        assert!(empty.contains("\"payload_len\":0"), "{empty}");
        assert!(empty.contains("\"kind\":\"gateway\""), "{empty}");
        // Missing/invalid inputs fail client-side.
        assert!(submit_command(&args(&["--network", "0000000000000001"])).is_err());
        assert!(submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000003",
            "--payload",
            "0",
            "--key",
            "00112233445566778899aabbccddeeff",
        ]))
        .is_err());
        assert!(submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000003",
            "--payload",
            "",
            "--key",
            "00112233445566778899aabbccddeeff",
            "--ttl-ms",
            "0",
        ]))
        .is_err());
        assert!(submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000003",
            "--payload",
            "",
            "--key",
            "short",
        ]))
        .is_err());
    }

    #[test]
    fn submit_generates_a_key_when_omitted() {
        let line = submit_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000003",
            "--payload",
            "",
        ]))
        .unwrap();
        let key = line
            .split("\"key\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap();
        assert_eq!(key.len(), 32, "{line}");
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()), "{line}");
        assert!(is_hex(&generate_key(), 32));
    }

    #[test]
    fn operation_get_commands_build_api1_lines() {
        let id = "abababababababababababababababab:0000000000000001";
        let line = operation_get_command(&args(&["--id", id])).unwrap();
        assert!(line.contains("\"method\":\"operations.get\""), "{line}");
        assert!(
            line.contains(&format!("\"operation_id\":\"{id}\"")),
            "{line}"
        );
        assert!(operation_get_command(&args(&["--id", "bogus"])).is_err());
        let line = operation_get_by_key_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--key",
            "00112233445566778899aabbccddeeff",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"operations.get_by_key\""),
            "{line}"
        );
        assert!(
            line.contains("\"key\":\"00112233445566778899aabbccddeeff\""),
            "{line}"
        );
        assert!(operation_get_by_key_command(&args(&["--network", "0000000000000001"])).is_err());
    }
}
