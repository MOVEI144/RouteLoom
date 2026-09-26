#[cfg(not(unix))]
compile_error!("routeloomctl v0.1 currently requires a Unix platform");

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod provision;
mod provision_office;

/// A query must never hang forever on a silent socket — but the read
/// budget still covers the longest daemon long-poll (`group-get --wait-ms`
/// up to 15 s) with margin. Streaming (`node-events`) clears the read
/// deadline after the first line and blocks until interrupted instead.
const CLI_READ_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// True when an API1 `command`'s `response` line carries `"ok":false`.
/// Only the envelope head is scanned — the verdict comes from the `ok`
/// member right after `request_id`, so a payload string that mentions
/// `"ok":false` cannot flip it. Legacy verbs have no envelope and never
/// fail here; a line that is not an API1 envelope at all fails closed
/// (success the CLI cannot confirm is not success).
fn api_response_is_error(command: &str, response: &str) -> bool {
    if !command.starts_with("API1 ") {
        return false;
    }
    let Some(rest) = response
        .trim_start()
        .strip_prefix("{\"v\":1,\"request_id\":")
    else {
        return true;
    };
    let after_id = if let Some(rest) = rest.strip_prefix("null") {
        rest
    } else if rest.starts_with('"') {
        // Request ids are `ctl-<pid>`; still skip escapes honestly.
        let mut chars = rest[1..].chars();
        let mut closed = false;
        let mut bytes = 1;
        while let Some(c) = chars.next() {
            bytes += c.len_utf8();
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    bytes += escaped.len_utf8();
                }
                continue;
            }
            if c == '"' {
                closed = true;
                break;
            }
        }
        if !closed {
            return true;
        }
        &rest[bytes..]
    } else {
        return true;
    };
    let Some(flag) = after_id.strip_prefix(",\"ok\":") else {
        return true;
    };
    if flag.starts_with("false") {
        true
    } else if flag.starts_with("true") {
        false
    } else {
        true
    }
}

/// Sends one `command` line and reads the first response line, bounded by
/// `read_timeout`/`write_timeout`. Returns the line plus the reader so the
/// caller can keep streaming (`node-events`) after printing it.
fn exchange_first(
    socket: &Path,
    command: &str,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(String, BufReader<UnixStream>), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(write_timeout))?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.is_empty() {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "daemon closed connection").into(),
        );
    }
    Ok((response, reader))
}

fn usage() {
    eprintln!(
        "Read-only daemon diagnostics: adapter | events [--follow [--kinds k1,k2]] | deliveries"
    );
    eprintln!(
        "routeloomctl [--socket PATH] status|diagnostics|autonomy|send <node> <hex>|receive --network <16hex> [--from earliest|latest | --cursor CURSOR] [--limit 1-32]|open-epoch --network <16hex>|submit --network <16hex> --epoch <16hex> --to <16hex> --payload <hex> [--key <32hex>] [--gateway [--scope SCOPE]] [--ttl-ms 1-30000] [--delivery BEST_EFFORT|RELIABLE] [--storage RAM_ONLY|HOST_DURABLE] [--hop-limit 1-10]|gateway-resolve --network <16hex> --gateway <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM [--expected-host <64hex>]|gateway-send --network <16hex> --epoch <16hex> --to <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM --payload <hex> [--key <32hex>] [--ttl-ms 1-30000] [--delivery BEST_EFFORT|RELIABLE] [--storage RAM_ONLY|HOST_DURABLE] [--hop-limit 1-10]|gateway-get --id <opid>|operation-get --id <opid>|operation-get-by-key --network <16hex> --epoch <16hex> --key <32hex>|config-challenge --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16>|config-status --network <16hex> --target <16hex> --config-namespace <u16> --operation-id <32hex>|config-retry --network <16hex> --target <16hex> --config-namespace <u16> --operation-id <32hex>|config-propose --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16> --base-snapshot <hex> --field <id>:<type>:<hex> [--field ...] [--apply-budget-ms <u32>]|config-recover --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16> --mode adopt-known|reprovision --new-store-generation <u32> --new-revision <u64> [--snapshot-hash <64hex>] [--baseline <hex>]|config-recovery-info --network <16hex> --target <16hex> --config-namespace <u16>|trust-install --network <16hex> --target <16hex> --manifest <file>|trust-status --network <16hex> --target <16hex>|config-get --id <cfg-opid>|cancel <opid>|nodes [--connected true|false] [--after <16hex>] [--limit 1-128]|node-get --node <16hex>|node-events (streams node_joined/node_left/link_changed until interrupted)|group-send --network <16hex> --group <1-65535|ALL> --payload <hex> [--key <32hex>] [--priority BULK|NORMAL|MANAGEMENT|URGENT] [--ordered] [--ttl-ms 1-30000] [--hop-limit 1-254] [--wait-ms 0-15000]|group-get --id <grp-opid> [--wait-ms 0-15000]"
    );
    eprintln!(
        "routeloomctl provision-keygen --root-id <16hex> --out <key.json>|provision-authority-keygen --authority-id <16hex> --out <key.json>|provision-image --spec <image-spec.json> --out <image.rlt1> [--nvs-dir <dir> [--credential <cred-spec.json>]]|provision-manifest --image <spec.json|image.rlt1> --key <root.key> --out <manifest.rtm1>|provision-verify --manifest <file> --current <spec.json|image.rlt1>  (local provisioning — no daemon socket)"
    );
    eprintln!(
        "routeloomctl provision-devca-keygen --device-ca-id <16hex> --out <devca.key>|provision-pop-challenge --node <16hex>|provision-devcert --ca-key <devca.key> --spec <identity-spec.json> --node <16hex> --serial <u32> --challenge <64hex> --pop <file> --out-dir <dir>|provision-identity --ca-key <devca.key> --spec <identity-spec.json> --node <16hex> --serial <u32> --out-dir <dir>|provision-siteca-keygen --site-ca-id <16hex> --out <siteca.key>|site-cert --ca-key <siteca.key> --site-id <16hex> --sak-pubkey <128hex> --network-low32 <8hex> --site-epoch <u32> --serial <u32> --out <sitecert.cwt>  (SDK v1 office tooling — no daemon socket)"
    );
    eprintln!(
        "routeloomctl site join-list|approve --request <jr-token> --device <16hex> --role endpoint|relay|gateway [--idempotency-key K]|deny --request <jr-token> --device <16hex> --reason not_here|blocked [--idempotency-key K]|policy [--zero-touch-open true|false] [--decision-mode kguard|closed] [--decision-timeout-ms 500-5000] [--pending-retry-after-s 30-3600]|members [--device <16hex> | [--after <16hex>] [--limit 1-128] [--include-removed]]|revoke --device <16hex> --expected-generation <u32> --reason removed|lost|replaced|blocked [--idempotency-key K]|gk-rotate [--expected-active-epoch <u32> [--idempotency-key K]]|cutover --expected-site-epoch <u32> --next-site-cert <hex> [--idempotency-key K]|status  (site authority over API1; cutover progress via operation-get --id <op-token>)"
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
    config_operation_request("config.status", network, target, ns, operation_id)
}

fn config_operation_request(
    method: &str,
    network: &str,
    target: &str,
    ns: u16,
    operation_id: &str,
) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"{method}\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns},\"operation_id\":\"{operation_id}\"}}}}",
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

/// Build the API1 `config.recover` request line — a signed RCR2 recovery
/// intent issued + transferred on the dedicated recovery lane, reachable
/// while the target journal is quarantined/uncertain. `mode` is
/// `adopt-known` (bind the proven survivor by `snapshot_hash`) or
/// `reprovision` (carry the complete `baseline` TLV to re-apply).
/// `snapshot_hash`/`baseline` are omitted when empty (reprovision without
/// an explicit hash / adopt-known carry neither field).
#[allow(clippy::too_many_arguments)]
fn config_recover_request(
    network: &str,
    target: &str,
    ns: u16,
    schema: u16,
    mode: &str,
    new_store_generation: u32,
    new_revision: u64,
    snapshot_hash: &str,
    baseline: &str,
) -> String {
    let hash_field = if snapshot_hash.is_empty() {
        String::new()
    } else {
        format!(",\"snapshot_hash\":\"{snapshot_hash}\"")
    };
    let baseline_field = if baseline.is_empty() {
        String::new()
    } else {
        format!(",\"baseline\":\"{baseline}\"")
    };
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.recover\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns},\"schema\":{schema},\"mode\":\"{mode}\",\"new_store_generation\":{new_store_generation},\"new_revision\":{new_revision}{hash_field}{baseline_field}}}}}",
        request_id(),
    )
}

/// Build the API1 `config.recovery_info` request line — reads the
/// target's RecoveryInfo (floor readings + survivor/testimony hashes)
/// the operator's RCR2 baseline binds.
fn config_recovery_info_request(network: &str, target: &str, ns: u16) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"config.recovery_info\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"config_namespace\":{ns}}}}}",
        request_id(),
    )
}

/// Build the API1 `trust.install` request line — delivers a signed trust
/// manifest (hex) on the kind-5 lane and reads back the TrustStatus
/// receipt. Independent of the config authority by design.
fn trust_install_request(network: &str, target: &str, manifest_hex: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"trust.install\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\",\"manifest\":\"{manifest_hex}\"}}}}",
        request_id(),
    )
}

/// Build the API1 `trust.status` request line — reads the target's
/// TrustStatus (install receipt + generation/image evidence).
fn trust_status_request(network: &str, target: &str) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"trust.status\",\"params\":{{\"network\":\"{network}\",\"target\":\"{target}\"}}}}",
        request_id(),
    )
}

/// Lowercase hex encoding for file bytes embedded in a request line.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
            "provision-authority-keygen" => {
                return provision::provision_authority_keygen_command(&remaining[1..])
            }
            "provision-image" => return provision::provision_image_command(&remaining[1..]),
            "provision-manifest" => return provision::provision_manifest_command(&remaining[1..]),
            "provision-verify" => return provision::provision_verify_command(&remaining[1..]),
            "provision-devca-keygen" => {
                return provision_office::provision_devca_keygen_command(&remaining[1..])
            }
            "provision-pop-challenge" => {
                return provision_office::provision_pop_challenge_command(&remaining[1..])
            }
            "provision-devcert" => {
                return provision_office::provision_devcert_command(&remaining[1..])
            }
            "provision-identity" => {
                return provision_office::provision_identity_command(&remaining[1..])
            }
            "provision-siteca-keygen" => {
                return provision_office::provision_siteca_keygen_command(&remaining[1..])
            }
            "site-cert" => return provision_office::site_cert_command(&remaining[1..]),
            _ => {}
        }
    }
    let command = match remaining.as_slice() {
        [name] if name == "status" => "STATUS".to_string(),
        [name] if name == "adapter" => "ADAPTER".to_string(),
        [name, rest @ ..] if name == "events" => events_command(rest)?,
        [name] if name == "deliveries" => "DELIVERIES".to_string(),
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
        [name, rest @ ..] if name == "config-retry" => config_retry_command(rest)?,
        [name, rest @ ..] if name == "config-propose" => config_propose_command(rest)?,
        [name, rest @ ..] if name == "config-recover" => config_recover_command(rest)?,
        [name, rest @ ..] if name == "config-recovery-info" => config_recovery_info_command(rest)?,
        [name, rest @ ..] if name == "trust-install" => trust_install_command(rest)?,
        [name, rest @ ..] if name == "trust-status" => trust_status_command(rest)?,
        [name, rest @ ..] if name == "config-get" => config_get_command(rest)?,
        [name, id] if name == "cancel" => cancel_command(id)?,
        [name, rest @ ..] if name == "nodes" => nodes_command(rest)?,
        [name, rest @ ..] if name == "node-get" => node_get_command(rest)?,
        [name] if name == "node-events" => node_events_request(),
        [name, rest @ ..] if name == "group-send" => group_send_command(rest)?,
        [name, rest @ ..] if name == "group-get" => group_get_command(rest)?,
        [name, rest @ ..] if name == "site" => site_command(rest)?,
        _ => {
            usage();
            return Err("invalid command".into());
        }
    };
    let streaming = is_streaming_command(&remaining);
    let (response, mut reader) =
        exchange_first(&socket, &command, CLI_READ_TIMEOUT, CLI_WRITE_TIMEOUT)?;
    print!("{response}");
    // The JSON stays on stdout either way; an API error only flips the
    // exit code, so scripts can rely on it without parsing.
    if api_response_is_error(&command, &response) {
        return Err("daemon answered an API error (response printed above)".into());
    }
    // Streaming verbs keep the connection open: every further line is one
    // subscription notification, printed as it arrives. The first line met
    // the query deadline; the tail waits until interrupted.
    if streaming {
        reader.get_mut().set_read_timeout(None)?;
        let stdout = io::stdout();
        for line in reader.lines() {
            let mut out = stdout.lock();
            writeln!(out, "{}", line?)?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Build the API1 `nodes.list` request line.
fn nodes_list_request(connected: Option<bool>, after: Option<&str>, limit: Option<u64>) -> String {
    let mut params = Vec::new();
    if let Some(connected) = connected {
        params.push(format!("\"connected\":{connected}"));
    }
    if let Some(after) = after {
        params.push(format!("\"after\":\"{after}\""));
    }
    if let Some(limit) = limit {
        params.push(format!("\"limit\":{limit}"));
    }
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"nodes.list\",\"params\":{{{}}}}}",
        request_id(),
        params.join(","),
    )
}

/// `nodes [--connected true|false] [--after <16hex>] [--limit 1-128]`:
/// the attached gateway's per-node link status (connected, last heard,
/// RSSI, link cost, route) — printed verbatim.
fn nodes_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut connected = None;
    let mut after = None;
    let mut limit = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connected" => {
                connected = Some(match opt_value(&mut args, "--connected")?.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err("--connected must be true or false".into()),
                })
            }
            "--after" => after = Some(want_hex16("--after", opt_value(&mut args, "--after")?)?),
            "--limit" => {
                let value = opt_value(&mut args, "--limit")?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| (1..=128).contains(n))
                    .ok_or("--limit must be an integer 1-128")?;
                limit = Some(value);
            }
            other => return Err(format!("unknown nodes option: {other}").into()),
        }
    }
    Ok(nodes_list_request(connected, after.as_deref(), limit))
}

/// `node-get --node <16hex>`: one node's link status (NOT_FOUND when the
/// gateway never reported it — "no communication").
fn node_get_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut node = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--node" => node = Some(want_hex16("--node", opt_value(&mut args, "--node")?)?),
            other => return Err(format!("unknown node-get option: {other}").into()),
        }
    }
    let node = node.ok_or("node-get requires --node <16hex>")?;
    Ok(format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"nodes.get\",\"params\":{{\"node\":\"{node}\"}}}}",
        request_id()
    ))
}

/// `node-events`: an events-stream subscription filtered to the membership
/// kinds; the connection stays open and notifications stream to stdout.
/// Verbs that hold the connection after the first line: every further
/// line is one subscription notification, printed until interrupted.
fn is_streaming_command(remaining: &[String]) -> bool {
    let Some(first) = remaining.first().map(String::as_str) else {
        return false;
    };
    if first == "node-events" {
        return true;
    }
    first == "events" && remaining.iter().any(|arg| arg == "--follow")
}

/// `events [--follow [--kinds k1,k2]]`: bare form keeps the one-shot
/// EVENTS ring dump; `--follow` replays the ring from the oldest entry
/// and then streams every event until interrupted. Redirect the follow
/// stream to a file for the post-mortem journal — it carries the boot
/// boundary, overflow markers, and heartbeats in-band.
fn events_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Ok("EVENTS".to_string());
    }
    let mut follow = false;
    let mut kinds: Option<Vec<String>> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--follow" => {
                follow = true;
                index += 1;
            }
            "--kinds" => {
                index += 1;
                let Some(list) = args.get(index) else {
                    return Err("events --kinds needs a comma-separated kind list".into());
                };
                let entries: Vec<String> = list.split(',').map(str::to_string).collect();
                if entries.iter().any(|entry| entry.is_empty()) {
                    return Err("events --kinds entries must be non-empty".into());
                }
                kinds = Some(entries);
                index += 1;
            }
            other => return Err(format!("events: unexpected argument {other}").into()),
        }
    }
    if !follow {
        return Err("events --kinds needs --follow".into());
    }
    let filter = kinds.map_or_else(String::new, |entries| {
        let joined = entries
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(",\"filter\":{{\"kinds\":[{joined}]}}")
    });
    Ok(format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"messages.subscribe\",\"params\":{{\"stream\":\"events\",\"from\":\"earliest\"{filter}}}}}",
        request_id(),
    ))
}

fn node_events_request() -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"messages.subscribe\",\"params\":{{\"stream\":\"events\",\"from\":\"latest\",\"filter\":{{\"kinds\":[\"node_joined\",\"node_left\",\"link_changed\"]}}}}}}",
        request_id()
    )
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
    // Message operations (`<lineage>:<seq>`) and Site Authority operations
    // (`op-<16hex>` from revoke/cutover/gk-rotate answers) share
    // `operations.get` — the daemon routes the `op-` tokens to the site
    // ledger, which is also where cutover progress is read.
    let well_formed = id
        .split_once(':')
        .is_some_and(|(lineage, seq)| is_hex(lineage, 32) && is_hex(seq, 16))
        || id
            .strip_prefix("op-")
            .or_else(|| id.strip_prefix("OP-"))
            .is_some_and(|token| is_hex(token, 16));
    if !well_formed {
        return Err("--id must be <32-hex lineage>:<16-hex sequence> or op-<16hex>".into());
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
    config_status_or_retry_command(args, false)
}

fn config_retry_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    config_status_or_retry_command(args, true)
}

fn config_status_or_retry_command(
    args: &[String],
    retry: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let name = if retry {
        "config-retry"
    } else {
        "config-status"
    };
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
            other => return Err(format!("unknown {name} option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or(format!("{name} requires --network <16hex>"))?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or(format!("{name} requires --target <16hex>"))?,
    )?;
    let ns = ns.ok_or(format!("{name} requires --config-namespace <u16>"))?;
    let operation_id = operation_id.ok_or(format!("{name} requires --operation-id <32hex>"))?;
    if !is_hex(&operation_id, 32) {
        return Err("--operation-id must be a 32-hex operation id".into());
    }
    let operation_id = operation_id.to_ascii_lowercase();
    Ok(if retry {
        config_operation_request("config.retry", &network, &target, ns, &operation_id)
    } else {
        config_status_request(&network, &target, ns, &operation_id)
    })
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

/// `config-recover --network <16hex> --target <16hex> --config-namespace
/// <u16> --schema <u16> --mode adopt-known|reprovision --new-store-generation
/// <u32> --new-revision <u64> [--snapshot-hash <64hex>] [--baseline <hex>]`.
/// Issues a signed RCR2 recovery intent on the dedicated recovery lane
/// (HostOps 0x24) — reachable while the target journal is
/// quarantined/uncertain. Read `config-recovery-info` first: adopt-known
/// binds the proven survivor hash, reprovision carries the complete
/// baseline TLV; (store generation, revision) must name the floor's exact
/// next. The real verdict arrives via `config-get`.
fn config_recover_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut ns: Option<u16> = None;
    let mut schema: Option<u16> = None;
    let mut mode: Option<String> = None;
    let mut store_gen: Option<u32> = None;
    let mut revision: Option<u64> = None;
    let mut snapshot_hash = String::new();
    let mut baseline = String::new();
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
            "--mode" => mode = Some(opt_value(&mut args, "--mode")?),
            "--new-store-generation" => {
                let raw = opt_value(&mut args, "--new-store-generation")?;
                store_gen = Some(
                    raw.parse::<u32>()
                        .map_err(|_| "--new-store-generation must be a u32")?,
                );
            }
            "--new-revision" => {
                let raw = opt_value(&mut args, "--new-revision")?;
                revision = Some(
                    raw.parse::<u64>()
                        .map_err(|_| "--new-revision must be a u64")?,
                );
            }
            "--snapshot-hash" => snapshot_hash = opt_value(&mut args, "--snapshot-hash")?,
            "--baseline" => baseline = opt_value(&mut args, "--baseline")?,
            other => return Err(format!("unknown config-recover option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("config-recover requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("config-recover requires --target <16hex>")?,
    )?;
    let ns = ns.ok_or("config-recover requires --config-namespace <u16>")?;
    let schema = schema.ok_or("config-recover requires --schema <u16>")?;
    let mode = mode.ok_or("config-recover requires --mode adopt-known|reprovision")?;
    if mode != "adopt-known" && mode != "reprovision" {
        return Err("--mode must be adopt-known or reprovision".into());
    }
    let store_gen = store_gen.ok_or("config-recover requires --new-store-generation <u32>")?;
    if store_gen == 0 {
        return Err("--new-store-generation must be nonzero".into());
    }
    let revision = revision.ok_or("config-recover requires --new-revision <u64>")?;
    if !snapshot_hash.is_empty() && !is_hex(&snapshot_hash, 64) {
        return Err("--snapshot-hash must be a 64-hex string".into());
    }
    if !baseline.is_empty()
        && (baseline.len() % 2 != 0
            || baseline.len() > 1024
            || !baseline.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("--baseline must be hex, at most 512 bytes".into());
    }
    if mode == "adopt-known" && !baseline.is_empty() {
        return Err("adopt-known carries no --baseline (the survivor is bound by hash)".into());
    }
    if mode == "adopt-known" && snapshot_hash.is_empty() {
        return Err("adopt-known requires --snapshot-hash <64hex>".into());
    }
    Ok(config_recover_request(
        &network,
        &target,
        ns,
        schema,
        &mode,
        store_gen,
        revision,
        &snapshot_hash.to_ascii_lowercase(),
        &baseline.to_ascii_lowercase(),
    ))
}

/// `config-recovery-info --network <16hex> --target <16hex>
/// --config-namespace <u16>`: reads the target's RecoveryInfo — the floor
/// readings and survivor/testimony hashes the RCR2 baseline binds. Run
/// this before `config-recover`: the recovery must name one past each
/// reported floor (the floor's exact next).
fn config_recovery_info_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut ns: Option<u16> = None;
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
            other => return Err(format!("unknown config-recovery-info option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("config-recovery-info requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("config-recovery-info requires --target <16hex>")?,
    )?;
    let ns = ns.ok_or("config-recovery-info requires --config-namespace <u16>")?;
    Ok(config_recovery_info_request(&network, &target, ns))
}

/// `trust-install --network <16hex> --target <16hex> --manifest <file>`:
/// delivers an offline-signed trust manifest (raw `.rtm1` bytes, as
/// `provision-manifest --out` writes them) on the kind-5 lane and reads
/// back the TrustStatus receipt. Needs no config authority by design —
/// a rotation works while the authority is being rebuilt.
fn trust_install_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut manifest: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => network = Some(opt_value(&mut args, "--network")?),
            "--target" => target = Some(opt_value(&mut args, "--target")?),
            "--manifest" => manifest = Some(opt_value(&mut args, "--manifest")?),
            other => return Err(format!("unknown trust-install option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("trust-install requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("trust-install requires --target <16hex>")?,
    )?;
    let path = manifest.ok_or("trust-install requires --manifest <file>")?;
    let bytes = std::fs::read(&path).map_err(|_| format!("cannot read manifest file {path}"))?;
    if bytes.is_empty() || bytes.len() > 2048 {
        return Err("manifest must be 1-2048 bytes of signed trust envelope".into());
    }
    Ok(trust_install_request(
        &network,
        &target,
        &hex_encode(&bytes),
    ))
}

/// `trust-status --network <16hex> --target <16hex>`: reads the target's
/// TrustStatus — the install receipt and the generation/image evidence
/// for a rotation.
fn trust_status_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network: Option<String> = None;
    let mut target: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => network = Some(opt_value(&mut args, "--network")?),
            "--target" => target = Some(opt_value(&mut args, "--target")?),
            other => return Err(format!("unknown trust-status option: {other}").into()),
        }
    }
    let network = want_hex16(
        "--network",
        network.ok_or("trust-status requires --network <16hex>")?,
    )?;
    let target = want_hex16(
        "--target",
        target.ok_or("trust-status requires --target <16hex>")?,
    )?;
    Ok(trust_status_request(&network, &target))
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

/// `group-send --network <16hex> --group <1-65535|ALL> --payload <hex>
/// [--key <32hex>] [--priority BULK|NORMAL|MANAGEMENT|URGENT] [--ordered]
/// [--ttl-ms 1-30000] [--hop-limit 1-254] [--wait-ms 0-15000]`. Thin client
/// over `group.send`: one payload to every node of a group (ALL = 65535);
/// the daemon's record (group_op token, state, counts) is printed verbatim.
fn group_send_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut network = None;
    let mut group = None;
    let mut payload = None;
    let mut key = None;
    let mut priority = "NORMAL".to_string();
    let mut ordered = false;
    let mut ttl_ms: u64 = 5_000;
    let mut hop_limit: u64 = 10;
    let mut wait_ms: u64 = 0;
    let mut args = args.iter();
    let number = |flag: &str, value: String, range: std::ops::RangeInclusive<u64>| {
        value
            .parse::<u64>()
            .ok()
            .filter(|n| range.contains(n))
            .ok_or_else(|| {
                format!(
                    "{flag} must be an integer {}-{}",
                    range.start(),
                    range.end()
                )
            })
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--network" => {
                network = Some(want_hex16("--network", opt_value(&mut args, "--network")?)?)
            }
            "--group" => {
                let value = opt_value(&mut args, "--group")?;
                group = Some(if value.eq_ignore_ascii_case("all") {
                    "\"ALL\"".to_string()
                } else {
                    number("--group", value, 1..=65_535)?.to_string()
                });
            }
            "--payload" => payload = Some(opt_value(&mut args, "--payload")?),
            "--key" => key = Some(opt_value(&mut args, "--key")?),
            "--priority" => priority = opt_value(&mut args, "--priority")?,
            "--ordered" => ordered = true,
            "--ttl-ms" => {
                ttl_ms = number("--ttl-ms", opt_value(&mut args, "--ttl-ms")?, 1..=30_000)?
            }
            "--hop-limit" => {
                hop_limit = number("--hop-limit", opt_value(&mut args, "--hop-limit")?, 1..=254)?
            }
            "--wait-ms" => {
                wait_ms = number("--wait-ms", opt_value(&mut args, "--wait-ms")?, 0..=15_000)?
            }
            other => return Err(format!("unknown group-send option: {other}").into()),
        }
    }
    let network = network.ok_or("group-send requires --network <16hex>")?;
    let group = group.ok_or("group-send requires --group <1-65535|ALL>")?;
    let payload = payload.ok_or("group-send requires --payload <hex>")?;
    if payload.len() % 2 != 0 || !payload.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--payload must be even-length hex".into());
    }
    if payload.len() > 254 {
        return Err("--payload exceeds 127 bytes (group payload limit)".into());
    }
    if !matches!(
        priority.as_str(),
        "BULK" | "NORMAL" | "MANAGEMENT" | "URGENT"
    ) {
        return Err("--priority must be BULK|NORMAL|MANAGEMENT|URGENT".into());
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
    Ok(format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"group.send\",\"params\":{{\"network\":\"{network}\",\"group\":{group},\"key\":\"{key}\",\"payload_hex\":\"{}\",\"payload_len\":{},\"options\":{{\"priority\":\"{priority}\",\"ordered\":{ordered},\"ttl_ms\":{ttl_ms},\"hop_limit\":{hop_limit}}},\"wait_ms\":{wait_ms}}}}}",
        request_id(),
        payload.to_ascii_lowercase(),
        payload.len() / 2,
    ))
}

/// `group-get --id <grp-token> [--wait-ms 0-15000]`: one group send's
/// record; with --wait-ms the daemon answers once it is final (or the
/// window ends).
fn group_get_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut id: Option<String> = None;
    let mut wait_ms: u64 = 0;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => id = Some(opt_value(&mut args, "--id")?),
            "--wait-ms" => {
                wait_ms = opt_value(&mut args, "--wait-ms")?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n <= 15_000)
                    .ok_or("--wait-ms must be an integer 0-15000")?
            }
            other => return Err(format!("unknown group-get option: {other}").into()),
        }
    }
    let id = id.ok_or("group-get requires --id <grp-op-token>")?;
    let hex = id
        .strip_prefix("grp")
        .ok_or("group-get id must be a grp-prefixed op token")?;
    if !is_hex(hex, 16) {
        return Err("--id must be grp<16 hex>".into());
    }
    Ok(format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"group.get\",\"params\":{{\"group_op\":\"grp{}\",\"wait_ms\":{wait_ms}}}}}",
        request_id(),
        hex.to_ascii_lowercase(),
    ))
}

/// `site` family: Site Authority operations over API1 (`join.requests.list`,
/// `join.decide`, `join.policy.get/set`, `members.list/get`,
/// `membership.revoke`, `group_keys.rotate/status`, `membership.cutover`,
/// `site.status`). Prints the daemon's JSON verbatim; the exit code follows
/// the API envelope like every other command. Cutover progress is not a
/// method — it arrives as `cutover.progress` events and stays readable via
/// `operation-get --id <op-token>` from the cutover answer.
fn site_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let (sub, rest) = args
        .split_first()
        .ok_or("site requires a subcommand: join-list|approve|deny|policy|members|revoke|gk-rotate|cutover|status")?;
    match sub.as_str() {
        "join-list" => {
            if !rest.is_empty() {
                return Err("unknown site join-list option".into());
            }
            Ok(site_request("join.requests.list", String::new()))
        }
        "approve" => site_decide_command(rest, true),
        "deny" => site_decide_command(rest, false),
        "policy" => site_policy_command(rest),
        "members" => site_members_command(rest),
        "revoke" => site_revoke_command(rest),
        "gk-rotate" => site_gk_rotate_command(rest),
        "cutover" => site_cutover_command(rest),
        "status" => {
            if !rest.is_empty() {
                return Err("unknown site status option".into());
            }
            Ok(site_request("site.status", String::new()))
        }
        other => Err(format!("unknown site subcommand: {other}").into()),
    }
}

/// One `API1 {"v":1,...}` line for a site `method`; `params` is the
/// already-serialized inner object (without braces) or empty for `{}`.
fn site_request(method: &str, params: String) -> String {
    format!(
        "API1 {{\"v\":1,\"request_id\":\"{}\",\"method\":\"{method}\",\"params\":{{{params}}}}}",
        request_id(),
    )
}

/// A `jr-<16hex>` join request token → lowercased.
fn want_request_token(flag: &str, value: String) -> Result<String, Box<dyn std::error::Error>> {
    let hex = value
        .strip_prefix("jr-")
        .or_else(|| value.strip_prefix("JR-"))
        .ok_or_else(|| format!("{flag} must be a jr-<16hex> token"))?;
    if !is_hex(hex, 16) {
        return Err(format!("{flag} must be a jr-<16hex> token").into());
    }
    Ok(format!("jr-{}", hex.to_ascii_lowercase()))
}

/// An idempotency key: caller's (`--idempotency-key`, 1-64 printable ASCII
/// without spaces, the daemon rule) or a generated one, announced on
/// stderr like `submit --key` does.
fn want_idempotency_key(key: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    match key {
        Some(key) => {
            if key.is_empty() || key.len() > 64 || !key.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(
                    "--idempotency-key must be 1-64 printable ASCII characters without spaces"
                        .into(),
                );
            }
            Ok(key)
        }
        None => {
            let generated = generate_key();
            eprintln!("generated idempotency key: {generated}");
            Ok(generated)
        }
    }
}

/// `site approve|deny --request <jr-token> --device <16hex> --role R|...`.
fn site_decide_command(
    args: &[String],
    approve: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut request: Option<String> = None;
    let mut device: Option<String> = None;
    let mut role: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut idempotency_key: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--request" => request = Some(opt_value(&mut args, "--request")?),
            "--device" => device = Some(opt_value(&mut args, "--device")?),
            "--role" => role = Some(opt_value(&mut args, "--role")?),
            "--reason" => reason = Some(opt_value(&mut args, "--reason")?),
            "--idempotency-key" => {
                idempotency_key = Some(opt_value(&mut args, "--idempotency-key")?)
            }
            other => {
                return Err(format!(
                    "unknown site {} option: {other}",
                    if approve { "approve" } else { "deny" }
                )
                .into())
            }
        }
    }
    let request = want_request_token(
        "--request",
        request.ok_or("site approve|deny requires --request <jr-token>")?,
    )?;
    let device = want_hex16(
        "--device",
        device.ok_or("site approve|deny requires --device <16hex>")?,
    )?;
    let verdict = if approve {
        let role = role.ok_or("site approve requires --role endpoint|relay|gateway")?;
        if !["endpoint", "relay", "gateway"].contains(&role.as_str()) {
            return Err("site approve requires --role endpoint|relay|gateway".into());
        }
        if reason.is_some() {
            return Err("--reason does not apply to site approve".into());
        }
        format!("\"verdict\":\"allow\",\"role\":\"{role}\"")
    } else {
        let reason = reason.ok_or("site deny requires --reason not_here|blocked")?;
        if !["not_here", "blocked"].contains(&reason.as_str()) {
            return Err("site deny requires --reason not_here|blocked".into());
        }
        if role.is_some() {
            return Err("--role does not apply to site deny".into());
        }
        format!("\"verdict\":\"deny\",\"reason\":\"{reason}\"")
    };
    let key = want_idempotency_key(idempotency_key)?;
    Ok(site_request(
        "join.decide",
        format!("\"join_request_id\":\"{request}\",\"device_id\":\"{device}\",{verdict},\"idempotency_key\":\"{key}\""),
    ))
}

/// `site policy [flags...]`: bare reads (`join.policy.get`), any flag
/// writes (`join.policy.set`). Ranges are the daemon's (07 §2) and are
/// enforced there too — the CLI only checks the value shapes.
fn site_policy_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut zero_touch_open: Option<bool> = None;
    let mut decision_mode: Option<String> = None;
    let mut decision_timeout_ms: Option<u16> = None;
    let mut pending_retry_after_s: Option<u32> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--zero-touch-open" => {
                zero_touch_open = Some(
                    opt_value(&mut args, "--zero-touch-open")?
                        .parse::<bool>()
                        .map_err(|_| "--zero-touch-open must be true or false")?,
                )
            }
            "--decision-mode" => {
                let mode = opt_value(&mut args, "--decision-mode")?;
                if !["kguard", "closed"].contains(&mode.as_str()) {
                    return Err("--decision-mode must be kguard or closed".into());
                }
                decision_mode = Some(mode);
            }
            "--decision-timeout-ms" => {
                decision_timeout_ms = Some(
                    opt_value(&mut args, "--decision-timeout-ms")?
                        .parse::<u16>()
                        .map_err(|_| "--decision-timeout-ms must be an integer 500-5000")?,
                )
            }
            "--pending-retry-after-s" => {
                pending_retry_after_s = Some(
                    opt_value(&mut args, "--pending-retry-after-s")?
                        .parse::<u32>()
                        .map_err(|_| "--pending-retry-after-s must be an integer 30-3600")?,
                )
            }
            other => return Err(format!("unknown site policy option: {other}").into()),
        }
    }
    if zero_touch_open.is_none()
        && decision_mode.is_none()
        && decision_timeout_ms.is_none()
        && pending_retry_after_s.is_none()
    {
        return Ok(site_request("join.policy.get", String::new()));
    }
    let mut params = Vec::new();
    if let Some(open) = zero_touch_open {
        params.push(format!("\"zero_touch_open\":{open}"));
    }
    if let Some(mode) = decision_mode {
        params.push(format!("\"decision_mode\":\"{mode}\""));
    }
    if let Some(ms) = decision_timeout_ms {
        params.push(format!("\"decision_timeout_ms\":{ms}"));
    }
    if let Some(s) = pending_retry_after_s {
        params.push(format!("\"pending_retry_after_s\":{s}"));
    }
    Ok(site_request("join.policy.set", params.join(",")))
}

/// `site members [--after/--limit/--include-removed]` lists;
/// `site members --device <16hex>` reads one (`members.get`).
fn site_members_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut device: Option<String> = None;
    let mut after: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut include_removed = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--device" => device = Some(opt_value(&mut args, "--device")?),
            "--after" => after = Some(opt_value(&mut args, "--after")?),
            "--limit" => {
                limit = Some(
                    opt_value(&mut args, "--limit")?
                        .parse::<u64>()
                        .map_err(|_| "--limit must be an integer 1-128")?,
                )
            }
            "--include-removed" => include_removed = true,
            other => return Err(format!("unknown site members option: {other}").into()),
        }
    }
    if let Some(device) = device {
        if after.is_some() || limit.is_some() || include_removed {
            return Err("--device reads one member and takes no list options".into());
        }
        return Ok(site_request(
            "members.get",
            format!("\"device_id\":\"{}\"", want_hex16("--device", device)?),
        ));
    }
    let mut params = Vec::new();
    if let Some(after) = after {
        params.push(format!("\"after\":\"{}\"", want_hex16("--after", after)?));
    }
    if let Some(limit) = limit {
        if !(1..=128).contains(&limit) {
            return Err("--limit must be an integer 1-128".into());
        }
        params.push(format!("\"limit\":{limit}"));
    }
    if include_removed {
        params.push("\"include_removed\":true".to_string());
    }
    Ok(site_request("members.list", params.join(",")))
}

/// `site revoke --device <16hex> --expected-generation <u32> --reason R`.
fn site_revoke_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut device: Option<String> = None;
    let mut expected_generation: Option<u32> = None;
    let mut reason: Option<String> = None;
    let mut idempotency_key: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--device" => device = Some(opt_value(&mut args, "--device")?),
            "--expected-generation" => {
                expected_generation = Some(
                    opt_value(&mut args, "--expected-generation")?
                        .parse::<u32>()
                        .map_err(|_| "--expected-generation must be an integer >= 1")?,
                )
            }
            "--reason" => reason = Some(opt_value(&mut args, "--reason")?),
            "--idempotency-key" => {
                idempotency_key = Some(opt_value(&mut args, "--idempotency-key")?)
            }
            other => return Err(format!("unknown site revoke option: {other}").into()),
        }
    }
    let device = want_hex16(
        "--device",
        device.ok_or("site revoke requires --device <16hex>")?,
    )?;
    let expected_generation = expected_generation
        .filter(|v| *v >= 1)
        .ok_or("--expected-generation must be an integer >= 1")?;
    let reason = reason.ok_or("site revoke requires --reason removed|lost|replaced|blocked")?;
    if !["removed", "lost", "replaced", "blocked"].contains(&reason.as_str()) {
        return Err("site revoke requires --reason removed|lost|replaced|blocked".into());
    }
    let key = want_idempotency_key(idempotency_key)?;
    Ok(site_request(
        "membership.revoke",
        format!("\"device_id\":\"{device}\",\"expected_generation\":{expected_generation},\"reason\":\"{reason}\",\"idempotency_key\":\"{key}\""),
    ))
}

/// `site gk-rotate`: bare reads (`group_keys.status`), with
/// `--expected-active-epoch` rotates (`group_keys.rotate`).
fn site_gk_rotate_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut expected_active_epoch: Option<u32> = None;
    let mut idempotency_key: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expected-active-epoch" => {
                expected_active_epoch = Some(
                    opt_value(&mut args, "--expected-active-epoch")?
                        .parse::<u32>()
                        .map_err(|_| "--expected-active-epoch must be an integer >= 1")?,
                )
            }
            "--idempotency-key" => {
                idempotency_key = Some(opt_value(&mut args, "--idempotency-key")?)
            }
            other => return Err(format!("unknown site gk-rotate option: {other}").into()),
        }
    }
    match expected_active_epoch {
        None => {
            if idempotency_key.is_some() {
                return Err("--idempotency-key needs --expected-active-epoch to rotate".into());
            }
            Ok(site_request("group_keys.status", String::new()))
        }
        Some(epoch) => {
            if epoch < 1 {
                return Err("--expected-active-epoch must be an integer >= 1".into());
            }
            let key = want_idempotency_key(idempotency_key)?;
            Ok(site_request(
                "group_keys.rotate",
                format!("\"expected_active_epoch\":{epoch},\"idempotency_key\":\"{key}\""),
            ))
        }
    }
}

/// `site cutover --expected-site-epoch <u32> --next-site-cert <hex>`.
fn site_cutover_command(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut expected_site_epoch: Option<u32> = None;
    let mut next_site_cert: Option<String> = None;
    let mut idempotency_key: Option<String> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expected-site-epoch" => {
                expected_site_epoch = Some(
                    opt_value(&mut args, "--expected-site-epoch")?
                        .parse::<u32>()
                        .map_err(|_| "--expected-site-epoch must be an integer >= 1")?,
                )
            }
            "--next-site-cert" => next_site_cert = Some(opt_value(&mut args, "--next-site-cert")?),
            "--idempotency-key" => {
                idempotency_key = Some(opt_value(&mut args, "--idempotency-key")?)
            }
            other => return Err(format!("unknown site cutover option: {other}").into()),
        }
    }
    let expected_site_epoch = expected_site_epoch
        .filter(|v| *v >= 1)
        .ok_or("--expected-site-epoch must be an integer >= 1")?;
    let cert = next_site_cert.ok_or("site cutover requires --next-site-cert <hex>")?;
    // Even-length hex, daemon cap 2048 chars: the daemon would silently
    // drop a trailing half-byte, so the CLI refuses it instead.
    if !is_hex_max(&cert, 1024) || cert.is_empty() {
        return Err("--next-site-cert must be even-length hex up to 2048 chars".into());
    }
    let key = want_idempotency_key(idempotency_key)?;
    Ok(site_request(
        "membership.cutover",
        format!("\"expected_site_epoch\":{expected_site_epoch},\"next_site_cert\":\"{}\",\"idempotency_key\":\"{key}\"", cert.to_ascii_lowercase()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique socket path per test (parallel tests must not share one).
    fn test_socket_path(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "routeloomctl-test-{}-{}-{tag}.sock",
            std::process::id(),
            id
        ))
    }

    /// Serves one connection: reads the command line, then runs `answer`
    /// with the connected stream. Returns the path to query.
    fn serve_once(tag: &str, answer: impl FnOnce(UnixStream) + Send + 'static) -> PathBuf {
        let path = test_socket_path(tag);
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // Read the command line, then answer.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(!line.is_empty());
            answer(stream);
        });
        path
    }

    #[test]
    fn api_error_envelope_is_detected() {
        let api = "API1 {\"v\":1}";
        assert!(api_response_is_error(
            api,
            "{\"v\":1,\"request_id\":\"ctl-9\",\"ok\":false,\"error\":{\"code\":\"NOT_FOUND\",\"detail\":{\"message\":\"nope\"},\"retryable\":false}}\n"
        ));
        assert!(api_response_is_error(
            api,
            "{\"v\":1,\"request_id\":null,\"ok\":false,\"error\":{\"code\":\"INVALID_REQUEST\",\"detail\":{\"message\":\"request exceeds 8192 bytes\"},\"retryable\":false}}\n"
        ));
        assert!(!api_response_is_error(
            api,
            "{\"v\":1,\"request_id\":\"ctl-9\",\"ok\":true,\"result\":{}}\n"
        ));
        // A payload that mentions `"ok":false` must not flip the verdict.
        assert!(!api_response_is_error(
            api,
            "{\"v\":1,\"request_id\":\"ctl-9\",\"ok\":true,\"result\":{\"note\":\"say \\\"ok\\\":false\"}}\n"
        ));
        // Legacy verbs have no envelope and never fail here.
        assert!(!api_response_is_error(
            "STATUS",
            "{\"connected\":true,\"ok\":false}\n"
        ));
        // Not an envelope at all: fail closed.
        assert!(api_response_is_error(api, "{\"error\":\"broken\"}\n"));
        assert!(api_response_is_error(api, "garbage\n"));
    }

    #[test]
    fn error_envelope_round_trip_is_readable() {
        let path = serve_once("api-error", |stream| {
            let mut stream = stream;
            stream
                .write_all(
                    b"{\"v\":1,\"request_id\":\"ctl-9\",\"ok\":false,\"error\":{\"code\":\"NOT_FOUND\",\"detail\":{\"message\":\"nope\"},\"retryable\":false}}\n",
                )
                .unwrap();
        });
        let command = operation_get_request("abababababababababababababababab:0000000000000009");
        let (response, _) = exchange_first(
            &path,
            &command,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(response.contains("\"code\":\"NOT_FOUND\""), "{response}");
        assert!(api_response_is_error(&command, &response));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn silent_socket_times_out_instead_of_hanging() {
        let path = serve_once("silent", |_| {
            // Never answer: the query must time out, not hang.
            std::thread::sleep(Duration::from_secs(30));
        });
        let start = std::time::Instant::now();
        let error = exchange_first(
            &path,
            "STATUS",
            Duration::from_millis(100),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "query hung: {:?}",
            start.elapsed()
        );
        let kind = error
            .downcast_ref::<io::Error>()
            .map(io::Error::kind)
            .unwrap_or(io::ErrorKind::Other);
        assert!(
            matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
            "{error:?}"
        );
        std::fs::remove_file(&path).ok();
    }

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
    fn node_commands_build_api1_lines() {
        let line = nodes_command(&args(&[])).unwrap();
        assert!(
            line.contains("\"method\":\"nodes.list\",\"params\":{}"),
            "{line}"
        );
        let line = nodes_command(&args(&[
            "--connected",
            "false",
            "--after",
            "00000000000000AB",
            "--limit",
            "5",
        ]))
        .unwrap();
        assert!(line.contains(
            "\"params\":{\"connected\":false,\"after\":\"00000000000000ab\",\"limit\":5}"
        ));
        assert!(nodes_command(&args(&["--limit", "0"])).is_err());
        assert!(nodes_command(&args(&["--limit", "129"])).is_err());
        assert!(nodes_command(&args(&["--connected", "yes"])).is_err());
        assert!(nodes_command(&args(&["--after", "12"])).is_err());
        let line = node_get_command(&args(&["--node", "0000000000000002"])).unwrap();
        assert!(
            line.contains("\"method\":\"nodes.get\",\"params\":{\"node\":\"0000000000000002\"}")
        );
        assert!(node_get_command(&args(&[])).is_err());
        let line = node_events_request();
        assert!(line.contains("\"stream\":\"events\""));
        assert!(line.contains("\"kinds\":[\"node_joined\",\"node_left\",\"link_changed\"]"));
        // Every line is a parseable API1 envelope.
        for line in [
            nodes_list_request(Some(true), None, Some(128)),
            node_events_request(),
        ] {
            assert!(routeloom_json::parse(line.strip_prefix("API1 ").unwrap()).is_ok());
        }
    }

    #[test]
    fn events_command_dump_and_follow() {
        // Bare `events` keeps the one-shot EVENTS ring dump.
        assert_eq!(events_command(&args(&[])).unwrap(), "EVENTS");
        // `--follow` replays the ring from the oldest entry, then streams
        // every event until interrupted: redirect to a file for the
        // post-mortem journal.
        let line = events_command(&args(&["--follow"])).unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"messages.subscribe\""), "{line}");
        assert!(line.contains("\"stream\":\"events\""), "{line}");
        assert!(line.contains("\"from\":\"earliest\""), "{line}");
        assert!(!line.contains("\"filter\""), "{line}");
        assert!(routeloom_json::parse(line.strip_prefix("API1 ").unwrap()).is_ok());
        let line = events_command(&args(&["--follow", "--kinds", "boot,error"])).unwrap();
        assert!(line.contains("\"kinds\":[\"boot\",\"error\"]"), "{line}");
        assert!(routeloom_json::parse(line.strip_prefix("API1 ").unwrap()).is_ok());
        // --kinds without --follow, unknown flags, and empty kinds fail.
        assert!(events_command(&args(&["--kinds", "boot"])).is_err());
        assert!(events_command(&args(&["--follow", "--bogus"])).is_err());
        assert!(events_command(&args(&["--follow", "--kinds"])).is_err());
        assert!(events_command(&args(&["--follow", "--kinds", ""])).is_err());
        assert!(events_command(&args(&["--follow", "--kinds", "boot,,error"])).is_err());
        assert!(events_command(&args(&["extra"])).is_err());
    }

    #[test]
    fn streaming_verbs_hold_the_connection() {
        assert!(is_streaming_command(&args(&["node-events"])));
        assert!(is_streaming_command(&args(&["events", "--follow"])));
        assert!(is_streaming_command(&args(&[
            "events", "--follow", "--kinds", "boot"
        ])));
        assert!(!is_streaming_command(&args(&["events"])));
        assert!(!is_streaming_command(&args(&["status"])));
        assert!(!is_streaming_command(&args(&[])));
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
        // Site Authority `op-` tokens ride the same method (revoke/cutover
        // progress); the daemon routes them to the site ledger.
        let line = operation_get_command(&args(&["--id", "op-0000000000000001"])).unwrap();
        assert!(
            line.contains("\"operation_id\":\"op-0000000000000001\""),
            "{line}"
        );
        assert!(operation_get_command(&args(&["--id", "op-1"])).is_err());
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
        let retry = config_retry_command(&args(&[
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
        assert!(retry.contains("\"method\":\"config.retry\""), "{retry}");
        assert!(retry.contains("\"operation_id\":\"00112233445566778899aabbccddeeff\""));
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

    #[test]
    fn config_recover_builds_api1_line() {
        let base = [
            "--network",
            "0000000000000007",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "1",
            "--schema",
            "1",
            "--mode",
            "adopt-known",
            "--new-store-generation",
            "4",
            "--new-revision",
            "8",
            "--snapshot-hash",
            "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
        ];
        let line = config_recover_command(&args(&base)).unwrap();
        assert!(line.starts_with("API1 {"), "{line}");
        assert!(line.contains("\"method\":\"config.recover\""), "{line}");
        assert!(line.contains("\"mode\":\"adopt-known\""), "{line}");
        assert!(line.contains("\"new_store_generation\":4"), "{line}");
        assert!(line.contains("\"new_revision\":8"), "{line}");
        assert!(line.contains("\"snapshot_hash\":\"abab"), "{line}");
        assert!(!line.contains("baseline"), "{line}");
        // Reprovision carries the baseline instead of the hash.
        let line = config_recover_command(&args(&[
            "--network",
            "0000000000000007",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "1",
            "--schema",
            "1",
            "--mode",
            "reprovision",
            "--new-store-generation",
            "4",
            "--new-revision",
            "8",
            "--baseline",
            "AABB",
        ]))
        .unwrap();
        assert!(line.contains("\"mode\":\"reprovision\""), "{line}");
        assert!(line.contains("\"baseline\":\"aabb\""), "{line}");
        assert!(!line.contains("snapshot_hash"), "{line}");
        // Mode/hash/baseline cross-checks refuse before any socket opens.
        assert!(config_recover_command(&args(&base[..base.len() - 2])).is_err());
        let mut bad_mode = base.to_vec();
        bad_mode[9] = "attest";
        assert!(config_recover_command(&args(&bad_mode)).is_err());
        let mut with_baseline = base.to_vec();
        with_baseline.extend(["--baseline", "aabb"]);
        assert!(config_recover_command(&args(&with_baseline)).is_err());
        let mut bad_hash = base.to_vec();
        bad_hash[15] = "zzzz";
        assert!(config_recover_command(&args(&bad_hash)).is_err());
    }

    #[test]
    fn recovery_info_and_trust_commands_build_api1_lines() {
        let line = config_recovery_info_command(&args(&[
            "--network",
            "0000000000000007",
            "--target",
            "0000000000000009",
            "--config-namespace",
            "1",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"config.recovery_info\""),
            "{line}"
        );
        assert!(config_recovery_info_command(&args(&[])).is_err());
        let line = trust_status_command(&args(&[
            "--network",
            "0000000000000007",
            "--target",
            "0000000000000009",
        ]))
        .unwrap();
        assert!(line.contains("\"method\":\"trust.status\""), "{line}");
        assert!(trust_status_command(&args(&[])).is_err());
        // trust-install embeds the manifest file bytes as hex.
        let path =
            std::env::temp_dir().join(format!("routeloom-ctl-test-{}.rtm1", std::process::id()));
        std::fs::write(&path, [0xD2_u8, 0x84, 0x01]).unwrap();
        let line = trust_install_command(&args(&[
            "--network",
            "0000000000000007",
            "--target",
            "0000000000000009",
            "--manifest",
            path.to_str().unwrap(),
        ]))
        .unwrap();
        assert!(line.contains("\"method\":\"trust.install\""), "{line}");
        assert!(line.contains("\"manifest\":\"d28401\""), "{line}");
        assert!(trust_install_command(&args(&["--network", "1", "--target", "2"])).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn group_commands_build_api1_lines() {
        let line = group_send_command(&args(&[
            "--network",
            "0000000000000007",
            "--group",
            "all",
            "--payload",
            "50554D50",
            "--key",
            "000102030405060708090A0B0C0D0E0F",
            "--priority",
            "URGENT",
            "--wait-ms",
            "2000",
        ]))
        .unwrap();
        let doc = routeloom_json::parse(line.strip_prefix("API1 ").unwrap()).unwrap();
        assert_eq!(
            doc.get("method").and_then(routeloom_json::Json::as_str),
            Some("group.send")
        );
        assert!(line.contains("\"group\":\"ALL\""), "{line}");
        assert!(line.contains("\"key\":\"000102030405060708090a0b0c0d0e0f\""));
        assert!(line.contains("\"payload_hex\":\"50554d50\",\"payload_len\":4"));
        assert!(line.contains(
            "\"options\":{\"priority\":\"URGENT\",\"ordered\":false,\"ttl_ms\":5000,\"hop_limit\":10},\"wait_ms\":2000"
        ));
        let line = group_send_command(&args(&[
            "--network",
            "0000000000000007",
            "--group",
            "7",
            "--payload",
            "01",
            "--ordered",
            "--hop-limit",
            "254",
        ]))
        .unwrap();
        assert!(line.contains("\"group\":7,"), "{line}");
        assert!(line.contains("\"ordered\":true"));
        assert!(line.contains("\"hop_limit\":254"));
        assert!(routeloom_json::parse(line.strip_prefix("API1 ").unwrap()).is_ok());
        let base = ["--network", "0000000000000007", "--payload", "01"];
        for bad in [
            vec!["--group", "0"],
            vec!["--group", "65536"],
            vec!["--group", "7", "--payload", "0"],
            vec!["--group", "7", "--priority", "HIGH"],
            vec!["--group", "7", "--ttl-ms", "30001"],
            vec!["--group", "7", "--hop-limit", "255"],
            vec!["--group", "7", "--wait-ms", "15001"],
            vec!["--group", "7", "--key", "00"],
        ] {
            let mut words: Vec<&str> = base.to_vec();
            words.extend(bad.iter().copied());
            assert!(group_send_command(&args(&words)).is_err(), "{bad:?}");
        }
        let long = "00".repeat(128);
        assert!(group_send_command(&args(&[
            "--network",
            "0000000000000007",
            "--group",
            "7",
            "--payload",
            &long
        ]))
        .is_err());
        assert!(group_send_command(&args(&["--group", "7", "--payload", "01"])).is_err());

        let line = group_get_command(&args(&["--id", "grp00000001000000A1", "--wait-ms", "5000"]))
            .unwrap();
        assert!(line.contains(
            "\"method\":\"group.get\",\"params\":{\"group_op\":\"grp00000001000000a1\",\"wait_ms\":5000}"
        ));
        assert!(group_get_command(&args(&["--id", "cfg00000001000000a1"])).is_err());
        assert!(group_get_command(&args(&["--id", "grp1"])).is_err());
        assert!(group_get_command(&args(&[])).is_err());
    }

    #[test]
    fn site_commands_build_api1_lines() {
        // join-list / status: bare reads.
        let line = site_command(&args(&["join-list"])).unwrap();
        assert!(
            line.contains("\"method\":\"join.requests.list\",\"params\":{}"),
            "{line}"
        );
        let line = site_command(&args(&["status"])).unwrap();
        assert!(
            line.contains("\"method\":\"site.status\",\"params\":{}"),
            "{line}"
        );
        assert!(site_command(&args(&["join-list", "--x"])).is_err());
        assert!(site_command(&args(&[])).is_err());
        assert!(site_command(&args(&["bogus"])).is_err());

        // approve / deny: verdict owns exactly its parameter.
        let line = site_command(&args(&[
            "approve",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00A1000000001234",
            "--role",
            "relay",
            "--idempotency-key",
            "k1",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"join.decide\",\"params\":{\"join_request_id\":\"jr-0000000000000001\",\"device_id\":\"00a1000000001234\",\"verdict\":\"allow\",\"role\":\"relay\",\"idempotency_key\":\"k1\"}"),
            "{line}"
        );
        let line = site_command(&args(&[
            "deny",
            "--request",
            "JR-0000000000000002",
            "--device",
            "00a1000000001234",
            "--reason",
            "blocked",
            "--idempotency-key",
            "k2",
        ]))
        .unwrap();
        assert!(
            line.contains("\"verdict\":\"deny\",\"reason\":\"blocked\"")
                && line.contains("\"join_request_id\":\"jr-0000000000000002\""),
            "{line}"
        );
        // A generated key keeps the line valid when omitted.
        let line = site_command(&args(&[
            "approve",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--role",
            "endpoint",
        ]))
        .unwrap();
        assert!(line.contains("\"idempotency_key\":\""), "{line}");
        assert!(site_command(&args(&[
            "approve",
            "--request",
            "jr-1",
            "--device",
            "00a1000000001234",
            "--role",
            "endpoint"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "approve",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--role",
            "owner"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "approve",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--role",
            "endpoint",
            "--reason",
            "blocked"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "deny",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--reason",
            "maybe"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "deny",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--reason",
            "blocked",
            "--role",
            "endpoint"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "approve",
            "--request",
            "jr-0000000000000001",
            "--device",
            "00a1000000001234",
            "--role",
            "endpoint",
            "--idempotency-key",
            "has space"
        ]))
        .is_err());

        // policy: bare reads, flags write partial patches.
        let line = site_command(&args(&["policy"])).unwrap();
        assert!(
            line.contains("\"method\":\"join.policy.get\",\"params\":{}"),
            "{line}"
        );
        let line = site_command(&args(&[
            "policy",
            "--zero-touch-open",
            "true",
            "--decision-mode",
            "closed",
            "--decision-timeout-ms",
            "800",
            "--pending-retry-after-s",
            "120",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"join.policy.set\",\"params\":{\"zero_touch_open\":true,\"decision_mode\":\"closed\",\"decision_timeout_ms\":800,\"pending_retry_after_s\":120}"),
            "{line}"
        );
        let line = site_command(&args(&["policy", "--decision-mode", "kguard"])).unwrap();
        assert!(
            line.contains(
                "\"method\":\"join.policy.set\",\"params\":{\"decision_mode\":\"kguard\"}"
            ),
            "{line}"
        );
        assert!(site_command(&args(&["policy", "--zero-touch-open", "yes"])).is_err());
        assert!(site_command(&args(&["policy", "--decision-mode", "open"])).is_err());
        assert!(site_command(&args(&["policy", "--bogus", "1"])).is_err());

        // members: list by default, one read with --device.
        let line = site_command(&args(&[
            "members",
            "--after",
            "00A1000000001234",
            "--limit",
            "10",
            "--include-removed",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"members.list\",\"params\":{\"after\":\"00a1000000001234\",\"limit\":10,\"include_removed\":true}"),
            "{line}"
        );
        let line = site_command(&args(&["members", "--device", "00A1000000001234"])).unwrap();
        assert!(
            line.contains(
                "\"method\":\"members.get\",\"params\":{\"device_id\":\"00a1000000001234\"}"
            ),
            "{line}"
        );
        assert!(site_command(&args(&["members", "--limit", "0"])).is_err());
        assert!(site_command(&args(&["members", "--limit", "129"])).is_err());
        assert!(site_command(&args(&[
            "members",
            "--device",
            "00a1000000001234",
            "--limit",
            "1"
        ]))
        .is_err());

        // revoke.
        let line = site_command(&args(&[
            "revoke",
            "--device",
            "00a1000000001234",
            "--expected-generation",
            "3",
            "--reason",
            "lost",
            "--idempotency-key",
            "rm-1",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"membership.revoke\",\"params\":{\"device_id\":\"00a1000000001234\",\"expected_generation\":3,\"reason\":\"lost\",\"idempotency_key\":\"rm-1\"}"),
            "{line}"
        );
        assert!(site_command(&args(&[
            "revoke",
            "--device",
            "00a1000000001234",
            "--expected-generation",
            "0",
            "--reason",
            "lost"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "revoke",
            "--device",
            "00a1000000001234",
            "--expected-generation",
            "1",
            "--reason",
            "gone"
        ]))
        .is_err());

        // gk-rotate: bare reads status, epoch rotates.
        let line = site_command(&args(&["gk-rotate"])).unwrap();
        assert!(
            line.contains("\"method\":\"group_keys.status\",\"params\":{}"),
            "{line}"
        );
        let line = site_command(&args(&[
            "gk-rotate",
            "--expected-active-epoch",
            "2",
            "--idempotency-key",
            "gk-1",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"group_keys.rotate\",\"params\":{\"expected_active_epoch\":2,\"idempotency_key\":\"gk-1\"}"),
            "{line}"
        );
        assert!(site_command(&args(&["gk-rotate", "--expected-active-epoch", "0"])).is_err());
        assert!(site_command(&args(&["gk-rotate", "--idempotency-key", "k"])).is_err());

        // cutover.
        let line = site_command(&args(&[
            "cutover",
            "--expected-site-epoch",
            "2",
            "--next-site-cert",
            "AABBCC",
            "--idempotency-key",
            "co-1",
        ]))
        .unwrap();
        assert!(
            line.contains("\"method\":\"membership.cutover\",\"params\":{\"expected_site_epoch\":2,\"next_site_cert\":\"aabbcc\",\"idempotency_key\":\"co-1\"}"),
            "{line}"
        );
        assert!(site_command(&args(&[
            "cutover",
            "--expected-site-epoch",
            "2",
            "--next-site-cert",
            "abc"
        ]))
        .is_err());
        assert!(site_command(&args(&[
            "cutover",
            "--expected-site-epoch",
            "0",
            "--next-site-cert",
            "aa"
        ]))
        .is_err());
    }
}
