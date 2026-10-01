//! Bounded optional AppObject lane. USB fragments hold one payload; the
//! gateway owns mesh retries. Session loss never retries an object operation.
use crate::{Outbound, State};
use routeloom_peercred::Principal;
use routeloom_protocol::{Frame, FrameKind};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const CAP: u32 = routeloom_protocol::host_ops::CAP_APP_OBJECT_V1;
const REQUEST_BASE: u64 = 0x4f54_0000_0000_0000;
const RECORDS: usize = 64;
pub fn owns_request(request: u64) -> bool {
    request & 0xffff_0000_0000_0000 == REQUEST_BASE
}
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub node: u64,
    pub data: Vec<u8>,
    pub deadline_ms: u32,
    pub app_tag: u16,
    pub encoding: u8,
}
#[derive(Clone)]
pub struct Record {
    pub id: u32,
    boot: u64,
    pub principal: Principal,
    pub network: u64,
    pub key: [u8; 16],
    pub request: Request,
    pub state: &'static str,
    pub reason: u16,
    created: Instant,
    offset: usize,
    begun: bool,
    cancel: bool,
    session: u64,
    pending: Option<(u64, Instant, u8, usize)>,
    next_poll: Instant,
}
impl Record {
    pub fn json(&self) -> String {
        format!(
            "{{\"object_id\":\"{:016x}{:08x}\",\"state\":\"{}\",\"reason\":{},\"node\":\"{:016x}\"}}",
            self.boot, self.id, self.state, self.reason, self.request.node
        )
    }
    fn terminal(&self) -> bool {
        !matches!(self.state, "HOST_QUEUED" | "UPLOADING" | "IN_PROGRESS")
    }
}
struct Inner {
    boot: u64,
    records: Vec<Record>,
    next_id: u32,
    next_request: u64,
}
pub struct ObjectOps(Mutex<Inner>);
impl Default for ObjectOps {
    fn default() -> Self {
        Self::with_boot(u64::from_be_bytes(
            crate::mint_id128()[..8].try_into().unwrap_or([1; 8]),
        ))
    }
}
impl ObjectOps {
    pub fn with_boot(boot: u64) -> Self {
        Self(Mutex::new(Inner {
            boot,
            records: Vec::new(),
            next_id: 1,
            next_request: 1,
        }))
    }
    pub fn resolve_id(&self, token: &str) -> Option<u32> {
        if token.len() != 24 || !token.is_ascii() {
            return None;
        }
        let boot = u64::from_str_radix(&token[..16], 16).ok()?;
        let id = u32::from_str_radix(&token[16..], 16).ok()?;
        (boot == self.lock().boot && id != 0).then_some(id)
    }
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn submit(
        &self,
        principal: Principal,
        network: u64,
        key: [u8; 16],
        request: Request,
    ) -> Result<Record, &'static str> {
        let mut inner = self.lock();
        if let Some(record) = inner
            .records
            .iter()
            .find(|r| r.principal == principal && r.network == network && r.key == key)
        {
            return if record.request == request {
                Ok(record.clone())
            } else {
                Err("IDEMPOTENCY_CONFLICT")
            };
        }
        // Retained identities are boot scoped and never silently evicted.
        if inner.records.len() >= RECORDS
            || inner.next_id == 0
            || inner.records.iter().filter(|r| !r.terminal()).count() >= 4
        {
            return Err("BUSY");
        }
        let now = Instant::now();
        let recent = |r: &&Record| r.created.elapsed() < Duration::from_secs(60);
        if inner.records.iter().filter(recent).count() >= 12
            || inner
                .records
                .iter()
                .filter(|r| r.request.node == request.node)
                .filter(recent)
                .count()
                >= 2
        {
            return Err("RATE_LIMITED");
        }
        let record = Record {
            id: inner.next_id,
            boot: inner.boot,
            principal,
            network,
            key,
            request,
            state: "HOST_QUEUED",
            reason: 0,
            created: now,
            offset: 0,
            begun: false,
            cancel: false,
            session: 0,
            pending: None,
            next_poll: now,
        };
        inner.next_id = inner.next_id.wrapping_add(1);
        inner.records.push(record.clone());
        Ok(record)
    }
    pub fn known(&self, principal: &Principal, network: u64, key: &[u8; 16]) -> bool {
        self.lock()
            .records
            .iter()
            .any(|r| &r.principal == principal && r.network == network && &r.key == key)
    }
    pub fn get(&self, principal: &Principal, id: u32) -> Option<Record> {
        self.lock()
            .records
            .iter()
            .find(|r| &r.principal == principal && r.id == id)
            .cloned()
    }
    pub fn cancel(&self, principal: &Principal, id: u32) -> bool {
        let mut inner = self.lock();
        let Some(record) = inner
            .records
            .iter_mut()
            .find(|r| &r.principal == principal && r.id == id)
        else {
            return false;
        };
        if record.state == "HOST_QUEUED" {
            record.state = "CANCELLED_BEFORE_TX";
        } else if !record.terminal() {
            record.cancel = true;
        }
        true
    }
    pub fn request_pending_in_session(&self, request: u64, session: u64) -> bool {
        self.lock().records.iter().any(|record| {
            !record.terminal()
                && record.session == session
                && record.created.elapsed()
                    < Duration::from_millis(u64::from(record.request.deadline_ms))
                && record.pending.is_some_and(|(id, queued, _, _)| {
                    id == request && queued.elapsed() < Duration::from_secs(3)
                })
        })
    }
    pub fn reply(&self, request: u64, session: u64, bytes: &[u8]) {
        if bytes.len() != 13 || bytes[..2] != [1, 0x84] {
            return;
        }
        let id = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let phase = bytes[6];
        let reason = u16::from_be_bytes([bytes[7], bytes[8]]);
        let mut inner = self.lock();
        let Some(record) = inner
            .records
            .iter_mut()
            .find(|r| r.id == id && r.session == session)
        else {
            return;
        };
        if record.terminal() {
            return;
        }
        let Some((pending, _, sub, count)) = record.pending else {
            return;
        };
        if pending != request {
            return;
        }
        record.pending = None;
        record.reason = reason;
        let valid_terminal = matches!((phase, reason), (3 | 5 | 6, 0) | (4, 9) | (8, 5))
            || (phase == 7 && reason != 0);
        if reason != 0 && !valid_terminal {
            if sub == 0x82 && reason == 24 {
                record.next_poll = Instant::now() + Duration::from_millis(250);
                return;
            }
            record.state = "FAILED";
            return;
        }
        record.state = match phase {
            1 => "UPLOADING",
            2 => "IN_PROGRESS",
            3 => "DELIVERED",
            4 => "EXPIRED",
            5 => "CANCELLED_BEFORE_TX",
            6 => "INDETERMINATE",
            7 => "FAILED",
            8 => "UNSUPPORTED",
            _ => "FAILED",
        };
        if sub == 0x80 {
            record.begun = true;
        }
        if sub == 0x81 {
            record.offset += count;
        }
        record.next_poll = Instant::now() + Duration::from_millis(250);
    }
    pub fn step(
        &self,
        session: u64,
        network: u64,
        capable: bool,
        outbound: &mpsc::SyncSender<Outbound>,
    ) {
        let mut inner = self.lock();
        let Inner {
            records,
            next_request,
            ..
        } = &mut *inner;
        for record in records.iter_mut().filter(|r| !r.terminal()) {
            if record.created.elapsed()
                >= Duration::from_millis(u64::from(record.request.deadline_ms))
            {
                record.state = if record.session == 0 {
                    "NOT_SENT"
                } else {
                    "INDETERMINATE"
                };
                continue;
            }
            if record.session != 0 && record.session != session {
                record.state = "INDETERMINATE";
                continue;
            }
        }
        let active = records
            .iter()
            .position(|r| !r.terminal() && r.session != 0)
            .or_else(|| records.iter().position(|r| !r.terminal()));
        let Some(index) = active else {
            return;
        };
        let record = &mut records[index];
        if session == 0 || !capable {
            return;
        }
        if record.network != network {
            record.state = "NOT_SENT";
            return;
        }
        if let Some((_, sent, _, _)) = record.pending {
            if sent.elapsed() >= Duration::from_secs(3) {
                record.state = "INDETERMINATE";
            }
            return;
        }
        if Instant::now() < record.next_poll {
            return;
        }
        let sub = if record.cancel {
            0x83
        } else if !record.begun {
            0x80
        } else if record.offset < record.request.data.len() {
            0x81
        } else if record.state == "IN_PROGRESS" {
            0x85
        } else {
            0x82
        };
        let mut body = vec![1, sub];
        body.extend_from_slice(&record.id.to_be_bytes());
        let mut count = 0;
        match sub {
            0x80 => {
                body.extend_from_slice(&record.request.node.to_be_bytes());
                let remaining = u64::from(record.request.deadline_ms)
                    .saturating_sub(record.created.elapsed().as_millis() as u64)
                    as u32;
                body.extend_from_slice(&remaining.to_be_bytes());
                body.extend_from_slice(&record.request.app_tag.to_be_bytes());
                body.push(record.request.encoding);
                body.extend_from_slice(&(record.request.data.len() as u16).to_be_bytes());
            }
            0x81 => {
                count = (record.request.data.len() - record.offset).min(512);
                body.extend_from_slice(&(record.offset as u16).to_be_bytes());
                body.extend_from_slice(&(count as u16).to_be_bytes());
                body.extend_from_slice(&record.request.data[record.offset..record.offset + count]);
            }
            _ => {}
        }
        let request = REQUEST_BASE | *next_request;
        *next_request += 1;
        if outbound
            .try_send(Outbound::Seal(Frame {
                kind: FrameKind::HostOps,
                flags: 0,
                session,
                request,
                body,
            }))
            .is_ok()
        {
            record.session = session;
            record.pending = Some((request, Instant::now(), sub, count));
            record.state = if sub == 0x80 {
                "UPLOADING"
            } else {
                record.state
            };
        }
    }
}
pub fn once(state: &State, outbound: &mpsc::SyncSender<Outbound>) {
    let (current, network, capable) = {
        let Ok(session) = state.session.lock() else {
            return;
        };
        (
            if session.authenticated {
                session.id.unwrap_or(0)
            } else {
                0
            },
            session.network.unwrap_or(0),
            session.capability.is_some_and(|caps| caps & CAP != 0),
        )
    };
    let network = match state.site.as_ref().map(|site| site.network()) {
        Some(site) if network == (site & 0xffff_ffff) => site,
        _ => network,
    };
    state.object_ops.step(current, network, capable, outbound);
}

pub fn decode_base64(text: &str) -> Result<Vec<u8>, &'static str> {
    if text.len() > 5464 {
        return Err("TOO_LARGE");
    }
    if text.len() % 4 != 0 {
        return Err("INVALID_ARGUMENT");
    }
    let stripped = text.trim_end_matches('=');
    let padding = text.len() - stripped.len();
    if padding > 2 || stripped.bytes().any(|b| b == b'-' || b == b'_') {
        return Err("INVALID_ARGUMENT");
    }
    let translated = stripped.replace('+', "-").replace('/', "_");
    let data =
        crate::receive_log::b64url_decode_limit(&translated, 4097).ok_or("INVALID_ARGUMENT")?;
    if data.len() > 4096 {
        return Err("TOO_LARGE");
    }
    if data.is_empty() || (3 - data.len() % 3) % 3 != padding {
        return Err("INVALID_ARGUMENT");
    }
    Ok(data)
}

#[derive(Default)]
pub struct IngressAssembly {
    session: u64,
    prefix: Vec<u8>,
    data: Vec<u8>,
    started: Option<Instant>,
}
impl IngressAssembly {
    pub fn fragment(
        &mut self,
        session: u64,
        bytes: &[u8],
    ) -> Option<(crate::receive_log::Ingress, u16, u8)> {
        // 47-byte metadata followed by <=512 bytes. The invariant prefix
        // includes origin, boot, end context, object id, tag, length and digest.
        if bytes.len() < 47 || bytes[..2] != [1, 0x86] {
            return None;
        }
        let total = u16::from_be_bytes([bytes[25], bytes[26]]) as usize;
        let offset = u16::from_be_bytes([bytes[27], bytes[28]]) as usize;
        let count = u16::from_be_bytes([bytes[29], bytes[30]]) as usize;
        if total == 0
            || total > 4096
            || count == 0
            || count > 512
            || bytes.len() != 47 + count
            || offset + count > total
        {
            return None;
        }
        let mut prefix = bytes[..27].to_vec();
        prefix.extend_from_slice(&bytes[31..47]);
        if offset == 0
            && (self.session != session || self.prefix != prefix || self.started.is_none())
        {
            self.session = session;
            self.prefix = prefix.clone();
            self.data.clear();
            self.started = Some(Instant::now());
        }
        if self.session != session
            || self.prefix != prefix
            || self
                .started
                .is_none_or(|t| t.elapsed() > Duration::from_secs(10))
        {
            *self = Self::default();
            return None;
        }
        if offset < self.data.len() {
            if self.data.get(offset..offset + count) != Some(&bytes[47..]) {
                *self = Self::default();
            }
            return None;
        }
        if offset != self.data.len() {
            *self = Self::default();
            return None;
        }
        self.data.extend_from_slice(&bytes[47..]);
        if self.data.len() != total {
            return None;
        }
        let digest = routeloom_keysched::sha256(&[&self.data]);
        if digest[..16] != bytes[31..47] {
            *self = Self::default();
            return None;
        }
        let read32 = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let origin = u64::from_be_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ]);
        let ingress = crate::receive_log::Ingress {
            network: 0,
            gateway: None,
            origin,
            msg_session: read32(14),
            msg_seq: (u64::from(read32(18)) << 32) | u64::from(read32(10)),
            payload: std::mem::take(&mut self.data),
            assurance: None,
        };
        let tag = u16::from_be_bytes([bytes[22], bytes[23]]);
        let encoding = bytes[24];
        *self = Self::default();
        Some((ingress, tag, encoding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_and_session_boundaries() {
        let ops = ObjectOps::with_boot(17);
        let principal = Principal::UnixUid(1);
        let request = Request {
            node: 2,
            data: vec![1],
            deadline_ms: 30000,
            app_tag: 0,
            encoding: 0,
        };
        let first = ops
            .submit(principal.clone(), 3, [1; 16], request.clone())
            .unwrap();
        assert_eq!(ops.resolve_id("000000000000001100000001"), Some(first.id));
        assert_eq!(
            ObjectOps::with_boot(18).resolve_id("000000000000001100000001"),
            None
        );
        let mut other = request.clone();
        other.app_tag = 1;
        assert_eq!(
            ops.submit(principal.clone(), 3, [1; 16], other).err(),
            Some("IDEMPOTENCY_CONFLICT")
        );
        assert!(ops.get(&Principal::UnixUid(2), first.id).is_none());
        let (sender, _receiver) = mpsc::sync_channel(1);
        ops.step(10, 3, true, &sender);
        ops.step(11, 3, true, &sender);
        assert_eq!(
            ops.get(&principal, first.id).unwrap().state,
            "INDETERMINATE"
        );
    }
    #[test]
    fn reply_requires_identity_and_success() {
        for reason in [0u16, 18] {
            let ops = ObjectOps::with_boot(17);
            let principal = Principal::UnixUid(1);
            let record = ops
                .submit(
                    principal.clone(),
                    3,
                    [1; 16],
                    Request {
                        node: 2,
                        data: vec![1],
                        deadline_ms: 30000,
                        app_tag: 0,
                        encoding: 0,
                    },
                )
                .unwrap();
            let (sender, receiver) = mpsc::sync_channel(1);
            ops.step(10, 3, true, &sender);
            let Outbound::Seal(frame) = receiver.recv().unwrap() else {
                panic!("sealed object request");
            };
            assert_eq!(frame.session, 10, "bind the admitted HostLink session");
            let mut bytes = vec![1, 0x84];
            bytes.extend_from_slice(&record.id.to_be_bytes());
            bytes.push(3);
            bytes.extend_from_slice(&reason.to_be_bytes());
            bytes.extend_from_slice(&1u32.to_be_bytes());
            assert!(!crate::observation::owns_request(frame.request));
            assert!(!crate::remote_observation::owns_request(frame.request));
            assert!(!crate::telemetry::owns_request(frame.request));
            assert!(!crate::group::owns_request(frame.request));
            ops.reply(frame.request, 11, &bytes);
            ops.reply(frame.request + 1, 10, &bytes);
            assert_eq!(ops.get(&principal, record.id).unwrap().state, "UPLOADING");
            ops.reply(frame.request, 10, &bytes);
            assert_eq!(
                ops.get(&principal, record.id).unwrap().state,
                if reason == 0 { "DELIVERED" } else { "FAILED" }
            );
        }
    }
    #[test]
    fn base64_bounds_are_canonical() {
        for size in [1, 121, 122, 2048, 4096] {
            let data = vec![0x93; size];
            assert_eq!(
                decode_base64(&crate::receive_log::base64_encode(&data)),
                Ok(data)
            );
        }
        for invalid in ["", "AQ", "AB==", "AQ===", "A?=="] {
            assert!(decode_base64(invalid).is_err());
        }
        assert!(decode_base64(&crate::receive_log::base64_encode(&vec![1; 4097])).is_err());
    }
    #[test]
    fn writer_rejects_expired_object_commands() {
        for boundary in ["deadline", "reply_timeout", "session_lost"] {
            let state = State::default();
            {
                let mut session = state.session.lock().unwrap();
                session.authenticated = true;
                session.id = Some(10);
            }
            state
                .object_ops
                .submit(
                    Principal::UnixUid(1),
                    3,
                    [1; 16],
                    Request {
                        node: 2,
                        data: vec![1],
                        deadline_ms: 30000,
                        app_tag: 0,
                        encoding: 0,
                    },
                )
                .unwrap();
            let (sender, receiver) = mpsc::sync_channel(1);
            state.object_ops.step(10, 3, true, &sender);
            let Outbound::Seal(frame) = receiver.recv().unwrap() else {
                panic!("sealed object request");
            };
            assert!(crate::queued_diagnostic_is_live(&state, frame.request));
            {
                let mut inner = state.object_ops.lock();
                let record = &mut inner.records[0];
                match boundary {
                    "deadline" => record.created = Instant::now() - Duration::from_secs(30),
                    "reply_timeout" => {
                        record.pending.as_mut().unwrap().1 = Instant::now() - Duration::from_secs(3)
                    }
                    _ => record.state = "INDETERMINATE",
                }
            }
            assert!(
                !crate::queued_diagnostic_is_live(&state, frame.request),
                "{boundary}"
            );
        }
    }
    #[test]
    fn late_upload_reply_cannot_restart_terminal_operation() {
        let ops = ObjectOps::with_boot(17);
        let principal = Principal::UnixUid(1);
        let record = ops
            .submit(
                principal.clone(),
                3,
                [1; 16],
                Request {
                    node: 2,
                    data: vec![1],
                    deadline_ms: 30000,
                    app_tag: 0,
                    encoding: 0,
                },
            )
            .unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        ops.step(10, 3, true, &sender);
        let Outbound::Seal(frame) = receiver.recv().unwrap() else {
            panic!("sealed object request");
        };
        ops.lock().records[0].pending.as_mut().unwrap().1 = Instant::now() - Duration::from_secs(3);
        ops.step(10, 3, true, &sender);
        assert_eq!(
            ops.get(&principal, record.id).unwrap().state,
            "INDETERMINATE"
        );
        let mut bytes = vec![1, 0x84];
        bytes.extend_from_slice(&record.id.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 6]);
        ops.reply(frame.request, 10, &bytes);
        assert_eq!(
            ops.get(&principal, record.id).unwrap().state,
            "INDETERMINATE"
        );
        ops.step(10, 3, true, &sender);
        assert!(receiver.try_recv().is_err());
    }
}
