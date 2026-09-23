//! RouteLoom backend for [`MeshTransport`]: a thin client of the
//! routeloom-host daemon's API1 Unix socket (docs/spec/host.md §3, §9).
//!
//! | facade op | API1 |
//! |---|---|
//! | `send` | `operations.open_epoch` (once, cached) + `messages.submit` |
//! | `receive` | `messages.subscribe {stream:"messages", from:"latest"}` |
//! | `membership` | `messages.subscribe {stream:"events", filter.kinds:[node_joined,node_left,link_changed]}` |
//! | `link_status` | `nodes.get` (NOT_FOUND → [`LinkStatus::unknown`]) |
//! | `links` | `nodes.list`, following `next_after` |
//!
//! Each call opens its own connection (the daemon serves one request per
//! line; subscriptions own their connection for the stream's lifetime).
//! The OS credential of this process is the API1 principal: `send` needs the
//! SEND grant and `receive` the READ_PAYLOAD grant on `network`
//! (--api-acl-file); `membership`/`link_status`/`links` need no grant.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use routeloom_json::Json;

use crate::{
    Delivery, LinkStatus, MembershipEvent, MembershipKind, MembershipStream, MeshTransport,
    Message, MessageStream, NodeId, SendHandle, SendOptions, TransportError,
};

/// Event kinds the membership stream subscribes to.
pub const MEMBERSHIP_EVENT_KINDS: [&str; 3] = ["node_joined", "node_left", "link_changed"];

pub struct RouteLoomTransport {
    socket: PathBuf,
    network: u64,
    epoch: Mutex<Option<String>>,
    counter: AtomicU64,
}

fn protocol(detail: impl Into<String>) -> TransportError {
    TransportError::Protocol(detail.into())
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    (text.len() == 16 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(text, 16).ok())
        .flatten()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn opt_u32(value: Option<&Json>) -> Option<u32> {
    value
        .and_then(Json::as_u64)
        .and_then(|v| u32::try_from(v).ok())
}

/// Parses the daemon's node object (`nodes.list`/`nodes.get`/event
/// `status`) into the facade type. Null fields stay None.
pub fn link_status_from_json(node: &Json) -> Option<LinkStatus> {
    let id = node
        .get("node")
        .and_then(Json::as_str)
        .and_then(parse_hex_u64)?;
    Some(LinkStatus {
        node: id,
        connected: node.get("connected").and_then(Json::as_bool)?,
        last_heard_ms: node.get("last_heard_ms").and_then(Json::as_u64),
        rssi_dbm: node
            .get("rssi_dbm")
            .and_then(Json::as_i64)
            .and_then(|v| i32::try_from(v).ok()),
        rssi_avg_dbm: match node.get("rssi_avg_dbm") {
            Some(Json::Number(text)) => text.parse::<f64>().ok(),
            _ => None,
        },
        link_cost: opt_u32(node.get("link_cost")),
        route_metric: opt_u32(node.get("route_metric")),
        hops: opt_u32(node.get("hops")),
        next_hop: node
            .get("next_hop")
            .and_then(Json::as_str)
            .and_then(parse_hex_u64),
    })
}

/// Parses one event-ring entry (the `event` member of a notification) into
/// a membership event; None for other event kinds.
pub fn membership_from_event(event: &Json) -> Option<MembershipEvent> {
    let kind = match event.get("kind").and_then(Json::as_str)? {
        "node_joined" => MembershipKind::Joined,
        "node_left" => MembershipKind::Left,
        "link_changed" => MembershipKind::LinkChanged,
        _ => return None,
    };
    let reason_key = if kind == MembershipKind::LinkChanged {
        "change"
    } else {
        "reason"
    };
    Some(MembershipEvent {
        kind,
        node: event
            .get("node")
            .and_then(Json::as_str)
            .and_then(parse_hex_u64)?,
        reason: event
            .get(reason_key)
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string(),
        at_ms: event.get("ms").and_then(Json::as_u64).unwrap_or(0),
        status: event.get("status").and_then(link_status_from_json),
    })
}

fn message_from_record(record: &Json) -> Option<Message> {
    let message = record.get("message")?;
    Some(Message {
        source: record
            .get("origin")
            .and_then(Json::as_str)
            .and_then(parse_hex_u64)?,
        payload: unhex(record.get("payload_hex").and_then(Json::as_str)?)?,
        message_id: format!(
            "{}:{}",
            message.get("session").and_then(Json::as_str)?,
            message.get("sequence").and_then(Json::as_str)?
        ),
    })
}

/// Splits one API1 response line into its result or typed refusal.
fn result_of(line: &str) -> Result<Json, TransportError> {
    let root = routeloom_json::parse(line.trim_end())
        .map_err(|error| protocol(format!("invalid response JSON: {error}")))?;
    match root.get("ok").and_then(Json::as_bool) {
        Some(true) => root
            .get("result")
            .cloned()
            .ok_or_else(|| protocol("ok response without result")),
        Some(false) => {
            let error = root.get("error");
            Err(TransportError::Rejected {
                code: error
                    .and_then(|e| e.get("code"))
                    .and_then(Json::as_str)
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                message: error
                    .and_then(|e| e.get("detail"))
                    .and_then(|d| d.get("message"))
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string(),
                retryable: error
                    .and_then(|e| e.get("retryable"))
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
            })
        }
        None => Err(protocol("response without ok")),
    }
}

/// 128-bit idempotency key: OS entropy, with a clock/pid/counter fallback
/// that is still unique per process.
fn fresh_key(counter: u64) -> String {
    let mut bytes = [0_u8; 16];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok();
    if !filled || bytes.iter().all(|b| *b == 0) || bytes.iter().all(|b| *b == 0xff) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        bytes[..8].copy_from_slice(&now.to_be_bytes());
        bytes[8..12].copy_from_slice(&std::process::id().to_be_bytes());
        bytes[12..].copy_from_slice(&(counter as u32 | 1).to_be_bytes());
    }
    hex(&bytes)
}

impl RouteLoomTransport {
    /// `socket`: the daemon's API socket (routeloom-host `--socket`);
    /// `network`: the mesh network id sends and receives are scoped to.
    pub fn new(socket: impl Into<PathBuf>, network: u64) -> Self {
        Self {
            socket: socket.into(),
            network,
            epoch: Mutex::new(None),
            counter: AtomicU64::new(0),
        }
    }

    fn request_line(&self, method: &str, params: &str) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!(
            "API1 {{\"v\":1,\"request_id\":\"rlc-{}-{n}\",\"method\":\"{method}\",\"params\":{params}}}\n",
            std::process::id()
        )
    }

    fn connect(&self, method: &str, params: &str) -> Result<BufReader<UnixStream>, TransportError> {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.write_all(self.request_line(method, params).as_bytes())?;
        stream.flush()?;
        Ok(BufReader::new(stream))
    }

    /// One request/response exchange on a fresh connection.
    pub fn call(&self, method: &str, params: &str) -> Result<Json, TransportError> {
        let mut reader = self.connect(method, params)?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(protocol("daemon closed the connection"));
        }
        result_of(&line)
    }

    fn epoch(&self, reopen: bool) -> Result<String, TransportError> {
        let mut cached = self.epoch.lock().expect("epoch cache poisoned");
        if !reopen {
            if let Some(epoch) = cached.as_ref() {
                return Ok(epoch.clone());
            }
        }
        let result = self.call(
            "operations.open_epoch",
            &format!("{{\"network\":\"{:016x}\"}}", self.network),
        )?;
        let epoch = result
            .get("admission_epoch")
            .and_then(Json::as_str)
            .ok_or_else(|| protocol("open_epoch without admission_epoch"))?
            .to_string();
        *cached = Some(epoch.clone());
        Ok(epoch)
    }

    fn submit(
        &self,
        epoch: &str,
        key: &str,
        dest: NodeId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<Json, TransportError> {
        let params = format!(
            "{{\"network\":\"{:016x}\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"{dest:016x}\"}},\"payload_hex\":\"{}\",\"payload_len\":{},\"options\":{{\"delivery\":\"{}\",\"ttl_ms\":{},\"storage\":\"{}\",\"hop_limit\":{}}}}}",
            self.network,
            hex(payload),
            payload.len(),
            match options.delivery {
                Delivery::BestEffort => "BEST_EFFORT",
                Delivery::Reliable => "RELIABLE",
            },
            options.ttl_ms,
            if options.durable { "HOST_DURABLE" } else { "RAM_ONLY" },
            options.hop_limit,
        );
        self.call("messages.submit", &params)
    }

    /// Opens a subscription and returns its reader positioned after the ok
    /// line — every following line is a notification.
    fn subscribe(&self, params: &str) -> Result<BufReader<UnixStream>, TransportError> {
        let mut reader = self.connect("messages.subscribe", params)?;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(protocol("daemon closed the connection"));
        }
        result_of(&line)?;
        Ok(reader)
    }
}

/// Blocking notification iterator: yields parsed items, skips heartbeats,
/// surfaces gap/overflow markers as [`TransportError::Gap`], ends on EOF or
/// the `ended` notification.
struct Notifications<T> {
    reader: BufReader<UnixStream>,
    parse: fn(&Json) -> Option<Option<T>>,
    done: bool,
}

impl<T> Iterator for Notifications<T> {
    type Item = Result<T, TransportError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => self.done = true,
                Ok(_) => {
                    let root = match routeloom_json::parse(line.trim_end()) {
                        Ok(root) => root,
                        Err(error) => {
                            return Some(Err(protocol(format!("invalid notification: {error}"))))
                        }
                    };
                    match root.get("kind").and_then(Json::as_str) {
                        Some("heartbeat") => continue,
                        Some("ended") => self.done = true,
                        Some(kind @ ("gap" | "overflow")) => {
                            return Some(Err(TransportError::Gap(kind.to_string())))
                        }
                        _ => match (self.parse)(&root) {
                            Some(Some(item)) => return Some(Ok(item)),
                            Some(None) => continue, // not for this stream
                            None => {
                                return Some(Err(protocol("unparsable notification")));
                            }
                        },
                    }
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(TransportError::Io(error)));
                }
            }
        }
        None
    }
}

fn parse_message_notification(root: &Json) -> Option<Option<Message>> {
    match root.get("kind").and_then(Json::as_str) {
        Some("message") => Some(Some(message_from_record(root.get("record")?)?)),
        _ => Some(None),
    }
}

fn parse_event_notification(root: &Json) -> Option<Option<MembershipEvent>> {
    match root.get("kind").and_then(Json::as_str) {
        Some("event") => Some(membership_from_event(root.get("event")?)),
        _ => Some(None),
    }
}

impl MeshTransport for RouteLoomTransport {
    fn send(
        &self,
        dest: NodeId,
        payload: &[u8],
        options: &SendOptions,
    ) -> Result<SendHandle, TransportError> {
        let key = fresh_key(self.counter.load(Ordering::Relaxed));
        let epoch = self.epoch(false)?;
        let result = match self.submit(&epoch, &key, dest, payload, options) {
            // The cached epoch was closed/forgotten by the daemon (restart,
            // rotation): reopen once and resubmit under the same key.
            Err(TransportError::Rejected { code, message, .. })
                if code == "EPOCH_CLOSED"
                    || (code == "INVALID_ARGUMENT" && message.contains("admission_epoch")) =>
            {
                let epoch = self.epoch(true)?;
                self.submit(&epoch, &key, dest, payload, options)?
            }
            other => other?,
        };
        let id = result
            .get("operation_id")
            .and_then(Json::as_str)
            .ok_or_else(|| protocol("submit without operation_id"))?;
        Ok(SendHandle { id: id.to_string() })
    }

    fn receive(&self) -> Result<MessageStream, TransportError> {
        let reader = self.subscribe(&format!(
            "{{\"stream\":\"messages\",\"network\":\"{:016x}\",\"from\":\"latest\"}}",
            self.network
        ))?;
        Ok(Box::new(Notifications {
            reader,
            parse: parse_message_notification,
            done: false,
        }))
    }

    fn membership(&self) -> Result<MembershipStream, TransportError> {
        let kinds: Vec<String> = MEMBERSHIP_EVENT_KINDS
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect();
        let reader = self.subscribe(&format!(
            "{{\"stream\":\"events\",\"from\":\"latest\",\"filter\":{{\"kinds\":[{}]}}}}",
            kinds.join(",")
        ))?;
        Ok(Box::new(Notifications {
            reader,
            parse: parse_event_notification,
            done: false,
        }))
    }

    fn link_status(&self, node: NodeId) -> Result<LinkStatus, TransportError> {
        match self.call("nodes.get", &format!("{{\"node\":\"{node:016x}\"}}")) {
            Ok(result) => result
                .get("node")
                .and_then(link_status_from_json)
                .ok_or_else(|| protocol("nodes.get without a node object")),
            Err(TransportError::Rejected { code, .. }) if code == "NOT_FOUND" => {
                Ok(LinkStatus::unknown(node))
            }
            Err(error) => Err(error),
        }
    }

    fn links(&self) -> Result<Vec<LinkStatus>, TransportError> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        // Bounded walk: the daemon's table holds at most 512 records and a
        // page carries up to 128, so 16 pages is a generous ceiling.
        for _ in 0..16 {
            let params = after
                .as_ref()
                .map_or_else(|| "{}".to_string(), |a| format!("{{\"after\":\"{a}\"}}"));
            let result = self.call("nodes.list", &params)?;
            let nodes = result
                .get("nodes")
                .and_then(Json::as_array)
                .ok_or_else(|| protocol("nodes.list without nodes"))?;
            for node in nodes {
                out.push(link_status_from_json(node).ok_or_else(|| protocol("bad node object"))?);
            }
            match result.get("next_after").and_then(Json::as_str) {
                Some(next) => after = Some(next.to_string()),
                None => return Ok(out),
            }
        }
        Err(protocol("nodes.list pagination did not terminate"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    /// Canned daemon: answers each connection's request line by method
    /// with a scripted response (plus notification lines for subscribe),
    /// recording the requests it saw.
    fn fake_daemon(
        dir: &Path,
        script: fn(&str, &Json) -> Vec<String>,
        connections: usize,
    ) -> (PathBuf, thread::JoinHandle<Vec<String>>) {
        let path = dir.join("api.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let mut seen = Vec::new();
            for stream in listener.incoming().take(connections) {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let body = line.trim_end().strip_prefix("API1 ").unwrap().to_string();
                let request = routeloom_json::parse(&body).unwrap();
                let method = request
                    .get("method")
                    .and_then(Json::as_str)
                    .unwrap()
                    .to_string();
                let params = request.get("params").cloned().unwrap();
                for out in script(&method, &params) {
                    stream.write_all(out.as_bytes()).unwrap();
                    stream.write_all(b"\n").unwrap();
                }
                seen.push(body);
            }
            seen
        });
        (path, handle)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rlc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const NODE2: &str = "{\"node\":\"0000000000000002\",\"role\":\"peer\",\"connected\":true,\"listed\":true,\"neighbor\":true,\"direct\":true,\"hops\":1,\"next_hop\":\"0000000000000002\",\"route_metric\":1,\"link_cost\":1,\"rssi_dbm\":-61,\"rssi_avg_dbm\":-60.50,\"telemetry_stale\":false,\"last_heard_ms\":1750,\"heard_age_ms\":1250,\"updated_ms\":2000,\"changed_ms\":2000}";
    const NODE9: &str = "{\"node\":\"0000000000000009\",\"role\":\"peer\",\"connected\":false,\"listed\":false,\"neighbor\":false,\"direct\":false,\"hops\":null,\"next_hop\":null,\"route_metric\":null,\"link_cost\":null,\"rssi_dbm\":null,\"rssi_avg_dbm\":null,\"telemetry_stale\":false,\"last_heard_ms\":null,\"heard_age_ms\":null,\"updated_ms\":2000,\"changed_ms\":2000}";

    fn ok(result: &str) -> String {
        format!("{{\"v\":1,\"request_id\":\"x\",\"ok\":true,\"result\":{result}}}")
    }

    #[test]
    fn link_status_and_links_map_the_daemon_node_object() {
        fn script(method: &str, params: &Json) -> Vec<String> {
            let source = "{\"state\":\"live\",\"gateway\":\"0000000000000001\",\"session_id\":5,\"synced_ms\":2000,\"tracked\":2,\"evicted\":0,\"clock\":\"host_unix_ms\"}";
            match (method, params.get("node").and_then(Json::as_str), params.get("after")) {
                ("nodes.get", Some("0000000000000002"), _) => {
                    vec![ok(&format!("{{\"source\":{source},\"node\":{NODE2}}}"))]
                }
                ("nodes.get", _, _) => vec!["{\"v\":1,\"request_id\":\"x\",\"ok\":false,\"error\":{\"code\":\"NOT_FOUND\",\"detail\":{\"message\":\"node not reported\"},\"retryable\":true}}".to_string()],
                ("nodes.list", _, None) => vec![ok(&format!(
                    "{{\"source\":{source},\"nodes\":[{NODE2}],\"next_after\":\"0000000000000002\"}}"
                ))],
                ("nodes.list", _, Some(_)) => vec![ok(&format!(
                    "{{\"source\":{source},\"nodes\":[{NODE9}],\"next_after\":null}}"
                ))],
                _ => vec![],
            }
        }
        let dir = temp_dir("links");
        let (path, daemon) = fake_daemon(&dir, script, 4);
        let transport = RouteLoomTransport::new(&path, 7);
        let status = transport.link_status(2).unwrap();
        assert!(status.connected);
        assert_eq!(status.rssi_dbm, Some(-61));
        assert_eq!(status.rssi_avg_dbm, Some(-60.5));
        assert_eq!(status.last_heard_ms, Some(1750));
        assert_eq!(
            (status.hops, status.link_cost, status.next_hop),
            (Some(1), Some(1), Some(2))
        );
        // Unreported node: honest "no communication", not an error.
        assert_eq!(
            transport.link_status(0x42).unwrap(),
            LinkStatus::unknown(0x42)
        );
        let links = transport.links().unwrap();
        assert_eq!(links.len(), 2);
        assert!(!links[1].connected && links[1].rssi_dbm.is_none() && links[1].hops.is_none());
        let seen = daemon.join().unwrap();
        assert!(seen[3].contains("\"after\":\"0000000000000002\""));
    }

    #[test]
    fn send_opens_an_epoch_then_submits() {
        fn script(method: &str, _: &Json) -> Vec<String> {
            match method {
                "operations.open_epoch" => vec![ok(
                    "{\"network\":\"0000000000000007\",\"admission_epoch\":\"00000000000000e1\"}",
                )],
                "messages.submit" => vec![ok(
                    "{\"operation_id\":\"op-1\",\"dispatch_state\":\"HOST_QUEUED\",\"evidence\":[\"HOST_RAM_RETAINED\"],\"message_key\":null}",
                )],
                _ => vec![],
            }
        }
        let dir = temp_dir("send");
        let (path, daemon) = fake_daemon(&dir, script, 3);
        let transport = RouteLoomTransport::new(&path, 7);
        let handle = transport
            .send(2, b"\x01\x02", &SendOptions::default())
            .unwrap();
        assert_eq!(handle.id, "op-1");
        // The epoch is cached: a second send is a single submit.
        let options = SendOptions {
            delivery: Delivery::BestEffort,
            durable: true,
            ..SendOptions::default()
        };
        transport.send(3, b"", &options).unwrap();
        let seen = daemon.join().unwrap();
        assert!(seen[0].contains("\"method\":\"operations.open_epoch\""));
        let submit = routeloom_json::parse(&seen[1]).unwrap();
        let params = submit.get("params").unwrap();
        assert_eq!(
            params.get("admission_epoch").and_then(Json::as_str),
            Some("00000000000000e1")
        );
        assert_eq!(
            params.get("payload_hex").and_then(Json::as_str),
            Some("0102")
        );
        assert_eq!(
            params
                .get("destination")
                .and_then(|d| d.get("id"))
                .and_then(Json::as_str),
            Some("0000000000000002")
        );
        assert_eq!(
            params.get("key").and_then(Json::as_str).map(str::len),
            Some(32)
        );
        assert!(seen[2].contains("\"delivery\":\"BEST_EFFORT\""));
        assert!(seen[2].contains("\"storage\":\"HOST_DURABLE\""));
    }

    #[test]
    fn streams_parse_notifications_and_surface_gaps() {
        fn script(_: &str, params: &Json) -> Vec<String> {
            let sub = "{\"v\":1,\"request_id\":\"x\",\"ok\":true,\"result\":{\"subscription\":\"sub0000000000000001\"}}".to_string();
            match params.get("stream").and_then(Json::as_str) {
                Some("messages") => vec![
                    sub,
                    "{\"subscription\":\"sub0000000000000001\",\"kind\":\"heartbeat\",\"n\":1,\"ms\":1}".into(),
                    "{\"subscription\":\"sub0000000000000001\",\"kind\":\"message\",\"n\":2,\"record\":{\"v\":1,\"network\":\"0000000000000007\",\"gateway\":\"0000000000000001\",\"origin\":\"0000000000000002\",\"message\":{\"session\":\"000007d2\",\"sequence\":\"0000000000000001\"},\"payload_hex\":\"6869\",\"payload_len\":2,\"cursor\":\"c\"}}".into(),
                    "{\"subscription\":\"sub0000000000000001\",\"kind\":\"gap\",\"n\":3,\"cause\":\"queue_overflow\"}".into(),
                ],
                _ => vec![
                    sub,
                    format!("{{\"subscription\":\"sub0000000000000002\",\"kind\":\"event\",\"n\":1,\"event\":{{\"seq\":4,\"ms\":900,\"kind\":\"node_left\",\"node\":\"0000000000000009\",\"gateway\":\"0000000000000001\",\"reason\":\"route_down\",\"status\":{NODE9}}}}}"),
                    format!("{{\"subscription\":\"sub0000000000000002\",\"kind\":\"event\",\"n\":2,\"event\":{{\"seq\":5,\"ms\":901,\"kind\":\"link_changed\",\"node\":\"0000000000000002\",\"gateway\":\"0000000000000001\",\"change\":\"next_hop\",\"status\":{NODE2}}}}}"),
                    "{\"subscription\":\"sub0000000000000002\",\"kind\":\"ended\",\"n\":3,\"reason\":\"closed\",\"delivered\":2,\"dropped\":0}".into(),
                ],
            }
        }
        let dir = temp_dir("streams");
        let (path, daemon) = fake_daemon(&dir, script, 2);
        let transport = RouteLoomTransport::new(&path, 7);
        let mut messages = transport.receive().unwrap();
        let first = messages.next().unwrap().unwrap();
        assert_eq!((first.source, first.payload.as_slice()), (2, &b"hi"[..]));
        assert_eq!(first.message_id, "000007d2:0000000000000001");
        assert!(matches!(messages.next(), Some(Err(TransportError::Gap(_)))));
        assert!(messages.next().is_none()); // EOF ends the stream

        let events: Vec<MembershipEvent> = transport
            .membership()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, MembershipKind::Left);
        assert_eq!(
            (events[0].node, events[0].reason.as_str(), events[0].at_ms),
            (9, "route_down", 900)
        );
        assert!(!events[0].status.as_ref().unwrap().connected);
        assert_eq!(events[1].kind, MembershipKind::LinkChanged);
        assert_eq!(events[1].reason, "next_hop");
        let seen = daemon.join().unwrap();
        assert!(seen[1].contains("\"kinds\":[\"node_joined\",\"node_left\",\"link_changed\"]"));
        assert!(seen[0].contains("\"from\":\"latest\""));
    }
}
