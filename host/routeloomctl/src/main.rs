#[cfg(not(unix))]
compile_error!("routeloomctl v0.1 currently requires a Unix platform");

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

mod provision;

fn usage() {
    eprintln!(
        "routeloomctl [--socket PATH] status|diagnostics|autonomy|send <node> <hex>|receive --network <16hex> [--from earliest|latest | --cursor CURSOR] [--limit 1-32]|open-epoch --network <16hex>|submit --network <16hex> --epoch <16hex> --to <16hex> --payload <hex> [--key <32hex>] [--gateway [--scope SCOPE]] [--ttl-ms 1-30000] [--delivery BEST_EFFORT|RELIABLE] [--storage RAM_ONLY|HOST_DURABLE] [--hop-limit 1-10]|gateway-resolve --network <16hex> --gateway <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM [--expected-host <64hex>]|gateway-send --network <16hex> --epoch <16hex> --to <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM --payload <hex> [--key <32hex>] [--ttl-ms 1-30000] [--delivery BEST_EFFORT|RELIABLE] [--storage RAM_ONLY|HOST_DURABLE] [--hop-limit 1-10]|gateway-get --id <opid>|operation-get --id <opid>|operation-get-by-key --network <16hex> --epoch <16hex> --key <32hex>|config-challenge --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16>|config-status --network <16hex> --target <16hex> --config-namespace <u16> --operation-id <32hex>|config-propose --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16> --base-snapshot <hex> --field <id>:<type>:<hex> [--field ...] [--apply-budget-ms <u32>]|config-get --id <cfg-opid>|cancel <opid>"
    );
    eprintln!(
        "routeloomctl provision-keygen --root-id <16hex> --out <key.json>|provision-image --spec <image-spec.json> --out <image.rlt1> [--nvs-dir <dir> [--credential <cred-spec.json>]]|provision-manifest --image <spec.json|image.rlt1> --key <root.key> --out <manifest.rtm1>|provision-verify --manifest <file> --current <spec.json|image.rlt1>  (local provisioning — no daemon socket)"
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
/// validated (and hex lowercased) by `submit_command`/`gateway_send_command`
/// before reaching here. `scope` is Some only for gateway destinations —
/// schema-2 requires it and node destinations reject it.
struct SubmitParams<'a> {
    network: &'a str,
    epoch: &'a str,
    key: &'a str,
    dest_kind: &'a str,
    dest: &'a str,
    scope: Option<&'a str>,
    payload_hex: &'a str,
    payload_len: usize,
    delivery: &'a str,
    ttl_ms: u64,
    storage: &'a str,
    hop_limit: u64,
}

/// Build the API1 `messages.submit` request line for the `submit` and
/// `gateway-send` commands.
fn submit_request(p: &SubmitParams<'_>) -> String {
    let scope = p
        .scope
        .map_or_else(String::new, |s| format!(",\"scope\":\"{s}\""));
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"{}\",\"admission_epoch\":\"{}\",\"key\":\"{}\",\"destination\":{{\"kind\":\"{}\",\"id\":\"{}\"{scope}}},\"payload_hex\":\"{}\",\"payload_len\":{},\"options\":{{\"delivery\":\"{}\",\"ttl_ms\":{},\"storage\":\"{}\",\"hop_limit\":{}}}}}}}",
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

/// Build the API1 `gateway.resolve` request line for `gateway-resolve`.
/// `expected_host` is required for HOST_RECEIVE_RAM and omitted for
/// GATEWAY_SDK_RAM (the daemon rejects a nonzero digest there).
fn gateway_resolve_request(
    network: &str,
    gateway: &str,
    scope: &str,
    expected_host: Option<&str>,
) -> String {
    let host = expected_host.map_or_else(String::new, |h| format!(",\"expected_host\":\"{h}\""));
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"gateway.resolve\",\"params\":{{\"network\":\"{network}\",\"gateway\":\"{gateway}\",\"scope\":\"{scope}\"{host}}}}}",
        request_id(),
    )
}

/// Build the API1 `gateway.get` request line for `gateway-get`.
fn gateway_get_request(id: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"gateway.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}",
        request_id(),
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

/// Build the API1 `operations.cancel` request line for the `cancel`
/// command. `id` is validated by `cancel_command` before reaching here.
fn cancel_request(id: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"operations.cancel\",\"params\":{{\"operation_id\":\"{id}\"}}}}",
        request_id(),
    )
}

/// Build the API1 `config.challenge` request line. `config_namespace`/`schema`
/// are emitted as JSON numbers (already u16-validated by the caller); the
/// network/target arrive lowercased 16-hex.
fn config_challenge_request(network: &str, target: &str, ns: u16, schema: u16) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.challenge\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns},\"schema\":{schema}}}}}",
        request_id(),
    )
}

/// Build the API1 `config.status` request line. `operation_id` is the 32-hex
/// id the verdict is read for — the status verb returns the real phase/reason,
/// never a claimed one.
fn config_status_request(network: &str, target: &str, ns: u16, operation_id: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.status\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns},\"operation_id\":\"{operation_id}\"}}}}",
        request_id(),
    )
}

/// Build the API1 `config.propose` request line. `patch` is a pre-built JSON
/// array of `{field_id, field_type, value}` entries (built by
/// `config_propose_command`, spliced in as a nested value — never a quoted
/// string). `apply_budget_ms` is omitted when the caller leaves it 0 (= use
/// the whole remaining challenge budget).
fn config_propose_request(
    network: &str,
    target: &str,
    ns: u16,
    schema: u16,
    base_snapshot: &str,
    patch: &str,
    apply_budget_ms: u32,
) -> String {
    let budget = if apply_budget_ms == 0 {
        String::new()
    } else {
        format!(",\"apply_budget_ms\":{apply_budget_ms}")
    };
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.propose\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns},\"schema\":{schema},\"base_snapshot\":\"{base_snapshot}\",\"patch\":{patch}{budget}}}}}",
        request_id(),
    )
}

/// Build the API1 `config.get` request line. `id` is the `cfg`-prefixed op
/// token the submit verbs return — the config op space, never operations.get.
fn config_get_request(id: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.get\",\"params\":{{\"config_op\":\"{id}\"}}}}",
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
    // provision-* are local operations — they build/sign/verify files and
    // never open the daemon socket (04-provisioning-lifecycle §4.4).
    if let Some(name) = remaining.first().map(String::as_str) {
        match name {
            "provision-keygen" => return provision::provision_keygen_command(&remaining[1..]),
            "provision-image" => return provision::provision_image_command(&remaining[1..]),
            "provision-manifest" => return provision::provision_manifest_command(&remaining[1..]),
            "provision-verify" => return provision::provision_verify_command(&remaining[1..]),
            _ => {}
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
        [name, rest @ ..] if name == "gateway-resolve" => gateway_resolve_command(rest)?,
        [name, rest @ ..] if name == "gateway-send" => gateway_send_command(rest)?,
        [name, rest @ ..] if name == "gateway-get" => gateway_get_command(rest)?,
        [name, rest @ ..] if name == "operation-get" => operation_get_command(rest)?,
        [name, rest @ ..] if name == "operation-get-by-key" => operation_get_by_key_command(rest)?,
        [name, rest @ ..] if name == "config-challenge" => config_challenge_command(rest)?,
        [name, rest @ ..] if name == "config-status" => config_status_command(rest)?,
        [name, rest @ ..] if name == "config-propose" => config_propose_command(rest)?,
        [name, rest @ ..] if name == "config-get" => config_get_command(rest)?,
        [name, id] if name == "cancel" => cancel_command(id)?,
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
    let mut scope: Option<String> = None;
    let mut payload: Option<String> = None;
    let mut ttl_ms: u64 = 5000;
    let mut delivery = "RELIABLE".to_string();
    // The CLI defaults to RAM_ONLY; HOST_DURABLE is passed through and
    // admitted only when the daemon runs with --op-store.
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
            "--scope" => {
                scope = Some(
                    args.next()
                        .ok_or("--scope requires HOST_RECEIVE_RAM|GATEWAY_SDK_RAM")?
                        .to_string(),
                )
            }
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
                    .ok_or("--delivery requires BEST_EFFORT|RELIABLE")?
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
    // The daemon advertises and accepts only BEST_EFFORT|RELIABLE — APPLIED
    // is a later phase (issue #12) and is refused here instead of letting a
    // request the daemon will reject leave the station.
    if !matches!(delivery.as_str(), "BEST_EFFORT" | "RELIABLE") {
        return Err("--delivery must be BEST_EFFORT|RELIABLE".into());
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
    // Schema-2 requires an explicit scope on a gateway destination; a
    // node destination must not carry one. `--gateway` without `--scope`
    // names the host receive mailbox — the only endpoint this daemon is.
    let scope = match (gateway, scope) {
        (false, Some(_)) => return Err("--scope is only valid with --gateway".into()),
        (false, None) => None,
        (true, provided) => {
            let scope = provided.unwrap_or_else(|| "HOST_RECEIVE_RAM".to_string());
            if !matches!(scope.as_str(), "HOST_RECEIVE_RAM" | "GATEWAY_SDK_RAM") {
                return Err("--scope must be HOST_RECEIVE_RAM|GATEWAY_SDK_RAM".into());
            }
            Some(scope)
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
        scope: scope.as_deref(),
        payload_hex: &payload_hex,
        payload_len,
        delivery: &delivery,
        ttl_ms,
        storage: &storage,
        hop_limit,
    }))
}

/// `gateway-resolve --network <16hex> --gateway <16hex> --scope
/// HOST_RECEIVE_RAM|GATEWAY_SDK_RAM [--expected-host <64hex>]`. Thin
/// client over `gateway.resolve`: the daemon answers whether the attached
/// gateway currently binds this host's receive endpoint — the result is
/// printed verbatim.
fn gateway_resolve_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut gateway: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut expected_host: Option<String> = None;
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
            "--gateway" => {
                gateway = Some(
                    args.next()
                        .ok_or("--gateway requires a 16-hex id")?
                        .to_string(),
                )
            }
            "--scope" => {
                scope = Some(
                    args.next()
                        .ok_or("--scope requires HOST_RECEIVE_RAM|GATEWAY_SDK_RAM")?
                        .to_string(),
                )
            }
            "--expected-host" => {
                expected_host = Some(
                    args.next()
                        .ok_or("--expected-host requires a 64-hex digest")?
                        .to_string(),
                )
            }
            other => return Err(format!("unknown gateway-resolve option: {other}").into()),
        }
    }
    let network = network.ok_or("gateway-resolve requires --network <16hex>")?;
    let gateway = gateway.ok_or("gateway-resolve requires --gateway <16hex>")?;
    let scope = scope.ok_or("gateway-resolve requires --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM")?;
    if !is_hex(&network, 16) {
        return Err("--network must be a 16-hex id".into());
    }
    if !is_hex(&gateway, 16) {
        return Err("--gateway must be a 16-hex id".into());
    }
    if !matches!(scope.as_str(), "HOST_RECEIVE_RAM" | "GATEWAY_SDK_RAM") {
        return Err("--scope must be HOST_RECEIVE_RAM|GATEWAY_SDK_RAM".into());
    }
    if let Some(host) = &expected_host {
        if !is_hex(host, 64) {
            return Err("--expected-host must be a 64-hex digest".into());
        }
    }
    Ok(gateway_resolve_request(
        &network.to_ascii_lowercase(),
        &gateway.to_ascii_lowercase(),
        &scope,
        expected_host
            .as_deref()
            .map(|h| h.to_ascii_lowercase())
            .as_deref(),
    ))
}

/// `gateway-send`: a schema-2 `messages.submit` — same options as
/// `submit` but the destination is a gateway and `--scope` is required
/// (explicitness over convenience for a host-bound endpoint). The daemon
/// mints the endpoint binding from its live registration; the caller
/// names only the destination gateway and scope.
fn gateway_send_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if !args.iter().any(|a| a == "--scope") {
        return Err("gateway-send requires --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM".into());
    }
    if args.iter().any(|a| a == "--gateway") {
        return Err("gateway-send implies --gateway; do not pass it".into());
    }
    let mut with_scope = vec!["--gateway".to_string()];
    with_scope.extend_from_slice(args);
    submit_command(&with_scope)
}

/// `gateway-get --id <opid>`: thin client over `gateway.get` — the
/// outcome query for a schema-2 submit. Prints the daemon's JSON result
/// verbatim.
fn gateway_get_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
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
            other => return Err(format!("unknown gateway-get option: {other}").into()),
        }
    }
    let id = id.ok_or("gateway-get requires --id <operation-id>")?;
    let well_formed = id
        .split_once(':')
        .is_some_and(|(lineage, seq)| is_hex(lineage, 32) && is_hex(seq, 16));
    if !well_formed {
        return Err("--id must be <32-hex lineage>:<16-hex sequence>".into());
    }
    Ok(gateway_get_request(&id.to_ascii_lowercase()))
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

/// `cancel <operation_id>`: thin client over `operations.cancel` — prints
/// the daemon's JSON result verbatim.
fn cancel_command(id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let well_formed = id
        .split_once(':')
        .is_some_and(|(lineage, seq)| is_hex(lineage, 32) && is_hex(seq, 16));
    if !well_formed {
        return Err("cancel requires <32-hex lineage>:<16-hex sequence>".into());
    }
    Ok(cancel_request(&id.to_ascii_lowercase()))
}

// --- config.* verbs (scope-gateway-config P5) --------------------------------
//
// Thin clients over the API1 config methods. Acceptance is NEVER a config
// verdict — the daemon answers PENDING and the real outcome is read with
// `config-get`. These verbs need PERM_CONFIG; a normal messages.send grant
// cannot reach them.

/// Decimal or `0x`-hex u16 — config namespaces, schemas, patch field ids.
fn parse_u16(text: &str) -> Option<u16> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => text.parse::<u16>().ok(),
    }
}

/// Even-length hex ≤ `max_bytes` — base snapshots and patch values. Empty is
/// allowed (the API accepts a zero-length snapshot/value).
fn is_hex_max(text: &str, max_bytes: usize) -> bool {
    text.len() % 2 == 0
        && text.len() <= max_bytes * 2
        && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `field_type` names — a number 1-4 is accepted too (the API maps both) and
/// normalised to the name the wire encoder documents.
fn config_field_type_name(text: &str) -> Option<&'static str> {
    match text.to_ascii_lowercase().as_str() {
        "bool" | "1" => Some("bool"),
        "u8" | "2" => Some("u8"),
        "u32" | "3" => Some("u32"),
        "bytes" | "4" => Some("bytes"),
        _ => None,
    }
}

/// Pull the value for `--flag` from the arg stream or report a missing value.
fn opt_value<'a>(
    args: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?
        .to_string())
}

/// A required 16-hex node/network id → lowercased.
fn want_hex16(flag: &str, value: String) -> Result<String, Box<dyn std::error::Error>> {
    if !is_hex(&value, 16) {
        return Err(format!("{flag} must be a 16-hex id").into());
    }
    Ok(value.to_ascii_lowercase())
}

/// A required u16 option (decimal or 0x-hex).
fn want_u16(flag: &str, value: String) -> Result<u16, Box<dyn std::error::Error>> {
    parse_u16(&value).ok_or_else(|| format!("{flag} must be a u16 (decimal or 0x-hex)").into())
}

/// `config-challenge --network <16hex> --target <16hex> --config-namespace
/// <u16> --schema <u16>`. Issues a ChallengeQuery for (target, namespace);
/// the ControlChallenge body — the freshness + CAS inputs a propose consumes
/// — arrives via `config-get` on the returned op token.
fn config_challenge_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut ns: Option<u16> = None;
    let mut schema: Option<u16> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => network = Some(opt_value(&mut args, "--network")?),
            "--target" => target = Some(opt_value(&mut args, "--target")?),
            "--config-namespace" => {
                ns = Some(want_u16(
                    "--config-namespace",
                    opt_value(&mut args, "--config-namespace")?,
                )?)
            }
            "--schema" => schema = Some(want_u16("--schema", opt_value(&mut args, "--schema")?)?),
            other => return Err(format!("unknown config-challenge option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("config-challenge requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("config-challenge requires --target <16hex>")?,
    )?;
    let ns = ns.ok_or("config-challenge requires --config-namespace <u16>")?;
    let schema = schema.ok_or("config-challenge requires --schema <u16>")?;
    Ok(config_challenge_request(&network, &target, ns, schema))
}

/// `config-status --network <16hex> --target <16hex> --config-namespace <u16>
/// --operation-id <32hex>`. Reads the real phase/reason verdict of the config
/// operation `operation_id` names — never a claimed one.
fn config_status_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut ns: Option<u16> = None;
    let mut operation_id: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => network = Some(opt_value(&mut args, "--network")?),
            "--target" => target = Some(opt_value(&mut args, "--target")?),
            "--config-namespace" => {
                ns = Some(want_u16(
                    "--config-namespace",
                    opt_value(&mut args, "--config-namespace")?,
                )?)
            }
            "--operation-id" => operation_id = Some(opt_value(&mut args, "--operation-id")?),
            other => return Err(format!("unknown config-status option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("config-status requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("config-status requires --target <16hex>")?,
    )?;
    let ns = ns.ok_or("config-status requires --config-namespace <u16>")?;
    let operation_id = operation_id.ok_or("config-status requires --operation-id <32hex>")?;
    if !is_hex(&operation_id, 32) {
        return Err("--operation-id must be a 32-hex operation id".into());
    }
    Ok(config_status_request(
        &network,
        &target,
        ns,
        &operation_id.to_ascii_lowercase(),
    ))
}

/// `config-propose --network <16hex> --target <16hex> --config-namespace
/// <u16> --schema <u16> --base-snapshot <hex≤512B> --field <id>:<type>:<hex>
/// [--field ...] [--apply-budget-ms <u32>]`. `--field` is repeatable (1-16
/// entries); `type` is bool|u8|u32|bytes (or 1-4). The daemon runs
/// challenge → sign → permit transfer → status; acceptance is PENDING, never
/// ACTIVE — the verdict is read with `config-get`.
fn config_propose_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut ns: Option<u16> = None;
    let mut schema: Option<u16> = None;
    let mut base_snapshot: Option<String> = None;
    let mut fields: Vec<String> = Vec::new();
    let mut apply_budget_ms: u32 = 0;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => network = Some(opt_value(&mut args, "--network")?),
            "--target" => target = Some(opt_value(&mut args, "--target")?),
            "--config-namespace" => {
                ns = Some(want_u16(
                    "--config-namespace",
                    opt_value(&mut args, "--config-namespace")?,
                )?)
            }
            "--schema" => schema = Some(want_u16("--schema", opt_value(&mut args, "--schema")?)?),
            "--base-snapshot" => base_snapshot = Some(opt_value(&mut args, "--base-snapshot")?),
            "--field" => fields.push(opt_value(&mut args, "--field")?),
            "--apply-budget-ms" => {
                let raw = opt_value(&mut args, "--apply-budget-ms")?;
                apply_budget_ms = raw
                    .parse::<u32>()
                    .map_err(|_| "--apply-budget-ms must be a u32")?;
            }
            other => return Err(format!("unknown config-propose option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("config-propose requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("config-propose requires --target <16hex>")?,
    )?;
    let ns = ns.ok_or("config-propose requires --config-namespace <u16>")?;
    let schema = schema.ok_or("config-propose requires --schema <u16>")?;
    let base_snapshot = base_snapshot.ok_or("config-propose requires --base-snapshot <hex>")?;
    if !is_hex_max(&base_snapshot, 512) {
        return Err("--base-snapshot must be even-length hex ≤ 512 bytes".into());
    }
    if fields.is_empty() || fields.len() > 16 {
        return Err("config-propose requires 1-16 --field <id>:<type>:<hex> entries".into());
    }
    let mut patch = String::from("[");
    for (i, spec) in fields.iter().enumerate() {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("--field must be <id>:<type>:<hex> (got \"{spec}\")").into());
        }
        let field_id = want_u16("--field id", parts[0].to_string())?;
        let field_type = config_field_type_name(parts[1])
            .ok_or("--field type must be bool|u8|u32|bytes (or 1-4)")?;
        if !is_hex_max(parts[2], 96) {
            return Err("--field value must be even-length hex ≤ 96 bytes".into());
        }
        if i > 0 {
            patch.push(',');
        }
        patch.push_str(&format!(
            "{{\"field_id\":{field_id},\"field_type\":\"{field_type}\",\"value\":\"{}\"}}",
            parts[2].to_ascii_lowercase()
        ));
    }
    patch.push(']');
    Ok(config_propose_request(
        &network,
        &target,
        ns,
        schema,
        &base_snapshot.to_ascii_lowercase(),
        &patch,
        apply_budget_ms,
    ))
}

/// `config-get --id <cfg-token>`: thin client over `config.get` — reads one
/// config op's honest outcome (PENDING/CHALLENGED/STATUS/NO_CHANGE/REFUSED/
/// TIMEOUT/INDETERMINATE/…). The `cfg` prefix marks the config op space — it
/// never collides with messages.*/gateway.* ids.
fn config_get_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut id: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => id = Some(opt_value(&mut args, "--id")?),
            other => return Err(format!("unknown config-get option: {other}").into()),
        }
    }
    let id = id.ok_or("config-get requires --id <cfg-op-token>")?;
    // cfg<1-16 hex> — the daemon also accepts a bare hex id, but the ctl
    // requires the explicit cfg token so the op space is never ambiguous.
    let hex = id
        .strip_prefix("cfg")
        .ok_or("config-get id must be a cfg-prefixed op token")?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--id must be cfg<1-16 hex>".into());
    }
    Ok(config_get_request(&id.to_ascii_lowercase()))
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
        // Schema-2 carries the scope — `--gateway` alone names the host
        // receive mailbox; `--scope` overrides it.
        assert!(empty.contains("\"scope\":\"HOST_RECEIVE_RAM\""), "{empty}");
        let sdk = submit_command(&args(&[
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
            "--scope",
            "GATEWAY_SDK_RAM",
        ]))
        .unwrap();
        assert!(sdk.contains("\"scope\":\"GATEWAY_SDK_RAM\""), "{sdk}");
        // --scope without --gateway is a client-side error; a bad scope
        // name is rejected before the wire too.
        assert!(submit_command(&args(&[
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
            "--scope",
            "HOST_RECEIVE_RAM",
        ]))
        .is_err());
        assert!(submit_command(&args(&[
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
            "--scope",
            "OTHER",
        ]))
        .is_err());
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
        // APPLIED is not a delivery the daemon accepts — the client refuses
        // it too rather than emit a request answered UNSUPPORTED.
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
            "--delivery",
            "APPLIED",
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

    #[test]
    fn cancel_builds_api1_line() {
        let line = cancel_command("ABABABABABABABABABABABABABABABAB:0000000000000001").unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"operations.cancel\""), "{line}");
        assert!(
            line.contains("\"operation_id\":\"abababababababababababababababab:0000000000000001\""),
            "{line}"
        );
        for bad in [
            "bogus",
            "abab:0000000000000001",
            "abababababababababababababababab:xyz",
        ] {
            assert!(cancel_command(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn gateway_resolve_builds_api1_line() {
        let line = gateway_resolve_command(&args(&[
            "--network",
            "0000000000000001",
            "--gateway",
            "0000000000000020",
            "--scope",
            "HOST_RECEIVE_RAM",
            "--expected-host",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ]))
        .unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"gateway.resolve\""), "{line}");
        assert!(line.contains("\"network\":\"0000000000000001\""), "{line}");
        assert!(line.contains("\"gateway\":\"0000000000000020\""), "{line}");
        assert!(line.contains("\"scope\":\"HOST_RECEIVE_RAM\""), "{line}");
        assert!(
            line.contains(
                "\"expected_host\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\""
            ),
            "{line}"
        );
        // SDK-scope resolve omits expected_host entirely.
        let sdk = gateway_resolve_command(&args(&[
            "--network",
            "0000000000000001",
            "--gateway",
            "0000000000000020",
            "--scope",
            "GATEWAY_SDK_RAM",
        ]))
        .unwrap();
        assert!(sdk.contains("\"scope\":\"GATEWAY_SDK_RAM\""), "{sdk}");
        assert!(!sdk.contains("expected_host"), "{sdk}");
        // Missing/invalid inputs fail client-side.
        assert!(gateway_resolve_command(&args(&["--network", "0000000000000001"])).is_err());
        assert!(gateway_resolve_command(&args(&[
            "--network",
            "0000000000000001",
            "--gateway",
            "0000000000000020",
            "--scope",
            "OTHER",
        ]))
        .is_err());
        assert!(gateway_resolve_command(&args(&[
            "--network",
            "0000000000000001",
            "--gateway",
            "zz",
            "--scope",
            "HOST_RECEIVE_RAM",
        ]))
        .is_err());
        assert!(gateway_resolve_command(&args(&[
            "--network",
            "0000000000000001",
            "--gateway",
            "0000000000000020",
            "--scope",
            "HOST_RECEIVE_RAM",
            "--expected-host",
            "short",
        ]))
        .is_err());
    }

    #[test]
    fn gateway_send_builds_schema2_submit() {
        let line = gateway_send_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--key",
            "00112233445566778899aabbccddeeff",
            "--to",
            "0000000000000020",
            "--scope",
            "HOST_RECEIVE_RAM",
            "--payload",
            "00FF80",
        ]))
        .unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"messages.submit\""), "{line}");
        assert!(line.contains("\"kind\":\"gateway\""), "{line}");
        assert!(line.contains("\"id\":\"0000000000000020\""), "{line}");
        assert!(line.contains("\"scope\":\"HOST_RECEIVE_RAM\""), "{line}");
        assert!(line.contains("\"payload_hex\":\"00ff80\""), "{line}");
        // --scope is required; --gateway is implied and refused.
        assert!(gateway_send_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000020",
            "--payload",
            "",
        ]))
        .is_err());
        assert!(gateway_send_command(&args(&[
            "--network",
            "0000000000000001",
            "--epoch",
            "0000000000000001",
            "--to",
            "0000000000000020",
            "--scope",
            "HOST_RECEIVE_RAM",
            "--payload",
            "",
            "--gateway",
        ]))
        .is_err());
    }

    #[test]
    fn gateway_get_builds_api1_line() {
        let id = "abababababababababababababababab:0000000000000001";
        let line = gateway_get_command(&args(&["--id", id])).unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"gateway.get\""), "{line}");
        assert!(
            line.contains(&format!("\"operation_id\":\"{id}\"")),
            "{line}"
        );
        assert!(gateway_get_command(&args(&["--id", "bogus"])).is_err());
        assert!(gateway_get_command(&args(&[])).is_err());
    }

    #[test]
    fn config_challenge_builds_api1_line() {
        let line = config_challenge_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--schema",
            "0x12",
        ]))
        .unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"config.challenge\""), "{line}");
        assert!(line.contains("\"network\":\"0000000000000001\""), "{line}");
        assert!(line.contains("\"target\":\"0000000000000009\""), "{line}");
        assert!(line.contains("\"config_namespace\":7"), "{line}");
        assert!(line.contains("\"schema\":18"), "{line}"); // 0x12 → 18
                                                           // Missing pieces and malformed ids are refused client-side.
        assert!(config_challenge_command(&args(&[])).is_err());
        assert!(config_challenge_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "zz",
            "--config-namespace",
            "7",
            "--schema",
            "1",
        ]))
        .is_err());
        assert!(config_challenge_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "70000",
            "--schema",
            "1",
        ]))
        .is_err());
    }

    #[test]
    fn config_status_builds_api1_line() {
        let line = config_status_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--operation-id",
            "00112233445566778899AABBCCDDEEFF",
        ]))
        .unwrap();
        assert!(line.contains("\"method\":\"config.status\""), "{line}");
        assert!(line.contains("\"config_namespace\":7"), "{line}");
        assert!(
            line.contains("\"operation_id\":\"00112233445566778899aabbccddeeff\""),
            "{line}"
        );
        assert!(config_status_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--operation-id",
            "tooshort",
        ]))
        .is_err());
    }

    #[test]
    fn config_propose_builds_api1_line() {
        let line = config_propose_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--schema",
            "1",
            "--base-snapshot",
            "aabb",
            "--field",
            "5:u32:0000002a",
            "--field",
            "1:bool:01",
            "--apply-budget-ms",
            "500",
        ]))
        .unwrap();
        assert!(line.contains("\"method\":\"config.propose\""), "{line}");
        assert!(line.contains("\"base_snapshot\":\"aabb\""), "{line}");
        // Both fields are emitted as a nested patch array, verbatim order.
        assert!(
            line.contains(
                "\"patch\":[{\"field_id\":5,\"field_type\":\"u32\",\"value\":\"0000002a\"},{\"field_id\":1,\"field_type\":\"bool\",\"value\":\"01\"}]"
            ),
            "{line}"
        );
        assert!(line.contains("\"apply_budget_ms\":500"), "{line}");
        // Zero budget is omitted entirely (daemon uses the whole challenge budget).
        let no_budget = config_propose_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--schema",
            "1",
            "--base-snapshot",
            "aabb",
            "--field",
            "5:u32:0000002a",
        ]))
        .unwrap();
        assert!(!no_budget.contains("apply_budget_ms"), "{no_budget}");
        // No fields, a bad field shape, an unknown type, or bad value hex fail.
        assert!(config_propose_command(&args(&[
            "--network",
            "0000000000000001",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "7",
            "--schema",
            "1",
            "--base-snapshot",
            "aabb",
        ]))
        .is_err());
        for bad in [
            "5:u32",
            "5:u32:zz:extra",
            "5:bogus:00",
            "5:u32:0",
            "x:u32:00",
        ] {
            assert!(
                config_propose_command(&args(&[
                    "--network",
                    "0000000000000001",
                    "--target",
                    "0000000000000009",
                    "--config-namespace",
                    "7",
                    "--schema",
                    "1",
                    "--base-snapshot",
                    "aabb",
                    "--field",
                    bad,
                ]))
                .is_err(),
                "--field {bad} should fail"
            );
        }
    }

    #[test]
    fn config_get_builds_api1_line() {
        let line = config_get_command(&args(&["--id", "cfg0000000000000007"])).unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"config.get\""), "{line}");
        assert!(
            line.contains("\"config_op\":\"cfg0000000000000007\""),
            "{line}"
        );
        // The cfg prefix is required — a bare hex id is rejected so the op
        // space is never ambiguous against messages.*/gateway.* tokens.
        assert!(config_get_command(&args(&["--id", "0000000000000007"])).is_err());
        assert!(config_get_command(&args(&["--id", "cfgzz"])).is_err());
        assert!(config_get_command(&args(&[])).is_err());
    }
}
