//! HostLink v2 (RLU1 protocol 2) session authentication for the USB bridge
//! (docs/spec/usb-protocol.md §2). A byte-for-byte port of
//! `components/routeloom/src/usb_session.cpp`; `protocol/usb-golden` pins
//! both ends to the same bytes.
//!
//! Every session value is keyed by
//! `K = HKDF-SHA-256(salt = empty, IKM = hostlink secret, info = "RouteLoom/v2/hostlink")`
//! and bound to the canonical transcript. The link is authenticated and
//! replay-protected, not encrypted.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{Frame, FrameKind, ProtocolError, VERSION};

pub const TAG_SIZE: usize = 16;
pub const SESSION_KEY_SIZE: usize = 32;
pub const BINDING_SIZE: usize = 32;
pub const MAX_PRINCIPAL_SIZE: usize = 32;
pub const PROTECTED_BODY_OVERHEAD: usize = 8 + TAG_SIZE;
pub const TRANSCRIPT_SIZE: usize =
    8 + 8 + 8 + 1 + 1 + 1 + 1 + BINDING_SIZE + 8 + 8 + 8 + 4 + 1 + MAX_PRINCIPAL_SIZE;
/// Transcript carrier byte for USB/serial. The 32-byte channel binding
/// after it is reserved for carriers that bind a secure channel and is all
/// zero on USB.
pub const CARRIER_USB_SERIAL: u8 = 0;

pub const DIRECTION_HOST_TO_DEVICE: u8 = 0;
pub const DIRECTION_DEVICE_TO_HOST: u8 = 1;
pub const FLAG_AUTH: u16 = 0x0001;
/// DataFromMesh flag bit marking the extended shape: the 8 B ingress
/// assurance tail follows the payload. Set only inside a 0x08-enabled
/// session, so a legacy host never meets a frame it cannot parse.
pub const FLAG_INGRESS_ASSURANCE: u16 = 0x0002;

pub const CREDIT_GRANT: u8 = 0;
pub const CREDIT_QUERY: u8 = 1;
pub const CREDIT_CLOSE: u8 = 2;

const TRANSCRIPT_MAGIC: u64 = 0x524c_5531_5452_4e32; // "RLU1TRN2"
const HOSTLINK_INFO: &[u8] = b"RouteLoom/v2/hostlink";

type HmacSha256 = Hmac<Sha256>;

/// Transcript bound into every session value: both nonces, the version
/// range the host offered and the selected version (downgrade binding),
/// carrier and channel binding, Node ID, Boot ID, full 64-bit Network ID,
/// capability bitmap and host principal.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub host_nonce: u64,
    pub device_nonce: u64,
    pub min_version: u8,
    pub max_version: u8,
    pub version: u8,
    pub carrier: u8,
    pub node: u64,
    pub boot: u64,
    pub network: u64,
    pub capability: u32,
    pub principal: Vec<u8>,
}

impl Transcript {
    /// A USB transcript for the only version this host speaks.
    pub fn usb(host_nonce: u64, device_nonce: u64, principal: &[u8]) -> Self {
        Self {
            host_nonce,
            device_nonce,
            min_version: VERSION,
            max_version: VERSION,
            version: VERSION,
            carrier: CARRIER_USB_SERIAL,
            node: 0,
            boot: 0,
            network: 0,
            capability: 0,
            principal: principal.to_vec(),
        }
    }

    /// Canonical encoding: "RLU1TRN2" || host_nonce || device_nonce ||
    /// min_version || max_version || version || carrier || binding (zero) ||
    /// node || boot || network || capability || plen || principal
    /// (zero-padded to TRANSCRIPT_SIZE). Principals longer than
    /// MAX_PRINCIPAL_SIZE are rejected rather than silently truncated —
    /// truncation would make two distinct principals collide.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.principal.len() > MAX_PRINCIPAL_SIZE {
            return Err(ProtocolError::PrincipalTooLong);
        }
        let mut out = Vec::with_capacity(TRANSCRIPT_SIZE);
        out.extend_from_slice(&TRANSCRIPT_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.host_nonce.to_be_bytes());
        out.extend_from_slice(&self.device_nonce.to_be_bytes());
        out.extend_from_slice(&[
            self.min_version,
            self.max_version,
            self.version,
            self.carrier,
        ]);
        out.extend_from_slice(&[0; BINDING_SIZE]);
        out.extend_from_slice(&self.node.to_be_bytes());
        out.extend_from_slice(&self.boot.to_be_bytes());
        out.extend_from_slice(&self.network.to_be_bytes());
        out.extend_from_slice(&self.capability.to_be_bytes());
        out.push(self.principal.len() as u8);
        out.extend_from_slice(&self.principal);
        out.resize(TRANSCRIPT_SIZE, 0);
        Ok(out)
    }
}

/// Session values for one transcript. Keys are wiped on drop; the type is
/// neither `Clone` nor `Debug`.
pub struct SessionProof {
    pub session_id: u64,
    pub key_h2d: [u8; SESSION_KEY_SIZE],
    pub key_d2h: [u8; SESSION_KEY_SIZE],
    pub hello_tag: [u8; TAG_SIZE],
    pub auth_tag: [u8; TAG_SIZE],
    pub auth_ok_tag: [u8; TAG_SIZE],
}

impl Drop for SessionProof {
    fn drop(&mut self) {
        self.session_id = 0;
        self.key_h2d.zeroize();
        self.key_d2h.zeroize();
        self.hello_tag.zeroize();
        self.auth_tag.zeroize();
        self.auth_ok_tag.zeroize();
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of any length; this cannot fail.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Every value is HMAC-SHA-256(K, label || 0x00 || transcript):
/// `key_h2d`/`key_d2h` (32 B), `hello`/`auth`/`auth-ok` tags (first 16 B)
/// and `session-id` (u64 BE of the first 8 B).
pub fn derive_session_proof(secret: &[u8], transcript: &[u8]) -> SessionProof {
    let mut hostlink_key = [0_u8; 32];
    // 32 B is far below HKDF's 255 * HashLen output limit.
    let _ = Hkdf::<Sha256>::new(None, secret).expand(HOSTLINK_INFO, &mut hostlink_key);
    let derive = |label: &[u8]| hmac_sha256(&hostlink_key, &[label, &[0], transcript]);
    let mut value = derive(b"session-id");
    let mut proof = SessionProof {
        session_id: u64::from_be_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]),
        key_h2d: derive(b"key-h2d"),
        key_d2h: derive(b"key-d2h"),
        hello_tag: [0; TAG_SIZE],
        auth_tag: [0; TAG_SIZE],
        auth_ok_tag: [0; TAG_SIZE],
    };
    for (label, out) in [
        (&b"hello"[..], &mut proof.hello_tag),
        (&b"auth"[..], &mut proof.auth_tag),
        (&b"auth-ok"[..], &mut proof.auth_ok_tag),
    ] {
        value = derive(label);
        out.copy_from_slice(&value[..TAG_SIZE]);
    }
    value.zeroize();
    hostlink_key.zeroize();
    proof
}

/// frame_tag = HMAC-SHA-256(key, dir || counter || kind || flags ||
/// request || inner)[..16], keyed with the direction's own key.
pub fn frame_tag(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    counter: u64,
    kind: FrameKind,
    flags: u16,
    request: u64,
    inner: &[u8],
) -> [u8; TAG_SIZE] {
    let mut mac = hmac_sha256(
        key,
        &[
            &[direction],
            &counter.to_be_bytes(),
            &[kind as u8],
            &flags.to_be_bytes(),
            &request.to_be_bytes(),
            inner,
        ],
    );
    let mut tag = [0_u8; TAG_SIZE];
    tag.copy_from_slice(&mac[..TAG_SIZE]);
    mac.zeroize();
    tag
}

/// Protected body layout: counter(8 BE) || tag(16) || inner.
pub fn seal_body(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    counter: u64,
    kind: FrameKind,
    flags: u16,
    request: u64,
    inner: &[u8],
) -> Vec<u8> {
    let tag = frame_tag(key, direction, counter, kind, flags, request, inner);
    let mut out = Vec::with_capacity(PROTECTED_BODY_OVERHEAD + inner.len());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(inner);
    out
}

/// Verifies the tag over the frame's own kind/flags/request, then returns
/// the embedded counter and the inner view. The caller enforces the
/// counter/replay policy.
pub fn open_body<'a>(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    frame: &'a Frame,
) -> Result<(u64, &'a [u8]), ProtocolError> {
    if frame.body.len() < PROTECTED_BODY_OVERHEAD {
        return Err(ProtocolError::FrameTooShort);
    }
    let (counter, rest) = frame.body.split_at(8);
    let (tag, inner) = rest.split_at(TAG_SIZE);
    let counter = u64::from_be_bytes(
        counter
            .try_into()
            .map_err(|_| ProtocolError::FrameTooShort)?,
    );
    let expected = frame_tag(
        key,
        direction,
        counter,
        frame.kind,
        frame.flags,
        frame.request,
        inner,
    );
    if !tags_equal(&expected, tag) {
        return Err(ProtocolError::TagMismatch);
    }
    Ok((counter, inner))
}

/// Constant-time comparison (no early exit on the first differing byte).
pub fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 A.3 (zero-length salt and info) through the exact HKDF
    /// call the session key uses.
    #[test]
    fn hkdf_matches_rfc5869_a3() {
        let mut okm = [0_u8; 42];
        Hkdf::<Sha256>::new(None, &[0x0b; 22])
            .expand(&[], &mut okm)
            .unwrap();
        assert_eq!(
            okm.to_vec(),
            unhex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8"
            )
        );
    }

    #[test]
    fn transcript_binds_version_range_secret_and_direction() {
        let mut transcript = Transcript::usb(1, 2, b"host");
        let good = derive_session_proof(b"secret", &transcript.encode().unwrap());
        transcript.max_version = 1;
        let narrowed = derive_session_proof(b"secret", &transcript.encode().unwrap());
        assert_ne!(good.auth_tag, narrowed.auth_tag, "offered range is bound");
        transcript.max_version = VERSION;
        transcript.network = 1_u64 << 32;
        let other_network = derive_session_proof(b"secret", &transcript.encode().unwrap());
        assert_ne!(
            good.hello_tag, other_network.hello_tag,
            "full network is bound"
        );
        let wrong =
            derive_session_proof(b"other", &Transcript::usb(1, 2, b"host").encode().unwrap());
        assert_ne!(good.hello_tag, wrong.hello_tag, "secret is bound");
        assert_ne!(good.key_h2d, good.key_d2h, "keys are per direction");
        let frame = Frame {
            kind: FrameKind::KeepAlive,
            flags: 0,
            session: good.session_id,
            request: 3,
            body: seal_body(
                &good.key_h2d,
                DIRECTION_HOST_TO_DEVICE,
                0,
                FrameKind::KeepAlive,
                0,
                3,
                b"x",
            ),
        };
        assert!(open_body(&good.key_h2d, DIRECTION_HOST_TO_DEVICE, &frame).is_ok());
        assert_eq!(
            open_body(&good.key_d2h, DIRECTION_HOST_TO_DEVICE, &frame).err(),
            Some(ProtocolError::TagMismatch)
        );
    }
}
