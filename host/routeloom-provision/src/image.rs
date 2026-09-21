//! `RLT1` `TrustStoreImage` codec — byte-for-byte mirror of
//! `components/routeloom/src/trust_store.cpp`
//! (04-provisioning-lifecycle.md §4.3.1). The record format IS the
//! contract: the manufactured-NVS path (P-A1) writes these bytes into
//! `rltrust` `t0`/`t1` and the device boot classifier must read them as a
//! committed, valid image.
//!
//! Layout (all integers big-endian; ≤2048-byte slot):
//! ```text
//!  0   u32  magic "RLT1" (0x524C5431)
//!  4   u16  format = 1
//!  6   u16  used_len (bytes incl. CRC)
//!  8   u32  schema_version = 1
//! 12   u32  seal (0 pending / 0x7A51C9E2 committed)
//! 16   u32  store_epoch | u32 min_authority_generation
//! 24   u64  network (FULL NetworkId) | u64 deployment_id
//! 40   u8 flags | u8 anchor_count | u8 key_count | u8 revocation_count
//! 44   u32 reserved = 0
//! 48   anchors[ac] × 80 | keys[kc] × 80 | revocations[rc] × 48
//! len-4 u32 crc32_iso_hdlc over [0, used_len-4)
//! ```
//! The signed manifest content is RLT1 bytes `[16, used_len-4)` — the
//! semantic body without the storage-local head and CRC tail.

use crate::crc32::crc32_iso_hdlc;
use crate::sha256::sha256;
use crate::{err, Code, Error, Result, BROADCAST_NODE_ID, INVALID_NODE_ID};

pub const TRUST_MAGIC: u32 = 0x524C_5431; // "RLT1"
pub const TRUST_FORMAT: u16 = 1;
pub const TRUST_SEAL_PENDING: u32 = 0;
pub const TRUST_SEAL_COMMITTED: u32 = 0x7A51_C9E2; // §4.3.1
pub const TRUST_STORE_SCHEMA_VERSION: u32 = 1;

pub const TRUST_STORE_SLOTS: usize = 2;
pub const TRUST_STORE_SLOT_BYTES: usize = 2048;
pub const TRUST_ANCHOR_MAX: usize = 2;
pub const TRUST_KEY_MAX: usize = 4;
pub const TRUST_REVOCATION_MAX: usize = 24;
pub const TRUST_ANCHOR_ENTRY_SIZE: usize = 80;
pub const TRUST_KEY_ENTRY_SIZE: usize = 80;
pub const TRUST_REVOCATION_ENTRY_SIZE: usize = 48;
pub const TRUST_IMAGE_HEADER_SIZE: usize = 48;
/// Maximum committed image: 48 + 2*80 + 4*80 + 24*48 + 4 = 1684.
pub const TRUST_IMAGE_MAX: usize = 1684;
/// Signed content = RLT1 bytes [16, used_len-4): TRUST_IMAGE_MAX - 16 - 4.
pub const TRUST_IMAGE_CONTENT_MAX: usize = 1664;

pub const FLAG_PROVISIONING_CONSOLE_LOCKED: u8 = 0x01;
pub const FLAG_REQUIRES_PRODUCTION_PROFILE: u8 = 0x02;
pub const FLAG_MASK: u8 = 0x03;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorStatus {
    Active = 1,
    Disabled = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyStatus {
    Staged = 1,
    Active = 2,
    Retired = 3,
    Revoked = 4,
}

/// §4.3.1 anchor entry: `root_id u64 | pubkey X||Y 64 | status u8 | reserved 7`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// Administrative 8-byte id assigned at key creation — the manifest
    /// kid names it. NOT a truncated key hash.
    pub root_id: u64,
    pub pubkey: [u8; 64],
    pub status: AnchorStatus,
}

/// §4.3.1 key entry: `authority_id u64 | generation u32 | profile u8 |
/// role u8 | status u8 | scope u8 | pubkey X||Y 64`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustKeyRecord {
    pub authority_id: u64,
    pub generation: u32,
    /// 1 = RLCP1_COSE_ESP256 (the only defined profile).
    pub profile: u8,
    /// 1 = config-issuer (other roles reserved).
    pub role: u8,
    pub status: KeyStatus,
    /// 0 = whole network (other values reserved).
    pub scope: u8,
    pub pubkey: [u8; 64],
}

/// §4.3.1 revocation entry: `node_id u64 | kid_fingerprint 32 |
/// revoked_at_epoch u32 | kind u8 | reserved 3`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRevocation {
    pub node_id: u64,
    pub kid_fingerprint: [u8; 32],
    pub revoked_at_epoch: u32,
    /// 1 = device credential (the only defined kind).
    pub kind: u8,
}

/// The semantic content of one trust image (RLT1 bytes [16, used_len-4)).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustImage {
    /// Ordinal, starts at 1, strictly increases per accepted image.
    pub store_epoch: u32,
    /// Deny permits signed under any key generation below this floor.
    pub min_authority_generation: u32,
    /// FULL NetworkId incl. the §4.8 deployment generation.
    pub network: u64,
    /// Operator audit label, not a credential.
    pub deployment_id: u64,
    pub flags: u8,
    pub anchors: Vec<TrustAnchor>,
    pub keys: Vec<TrustKeyRecord>,
    pub revocations: Vec<TrustRevocation>,
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// P-256 point-membership check — the host stand-in for
/// `uECC_valid_public_key` (SEC1 uncompressed-point decode, which also
/// enforces canonical coordinates; the vendored uECC check is point-on-
/// curve only, so a hypothetical non-canonical encoding that aliases to an
/// on-curve point would be rejected here — never emitted and never seen in
/// practice).
pub fn pubkey_on_curve(pubkey: &[u8; 64]) -> bool {
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    p256::PublicKey::from_sec1_bytes(&sec1).is_ok()
}

/// Structural size of an image encoding (used_len incl. CRC), or None
/// when the counts are out of range (device returns 0).
pub fn image_encoded_size(image: &TrustImage) -> Option<usize> {
    if image.anchors.len() > TRUST_ANCHOR_MAX
        || image.keys.len() > TRUST_KEY_MAX
        || image.revocations.len() > TRUST_REVOCATION_MAX
    {
        return None;
    }
    Some(
        TRUST_IMAGE_HEADER_SIZE
            + image.anchors.len() * TRUST_ANCHOR_ENTRY_SIZE
            + image.keys.len() * TRUST_KEY_ENTRY_SIZE
            + image.revocations.len() * TRUST_REVOCATION_ENTRY_SIZE
            + 4,
    )
}

/// Write the shared image body — RLT1 bytes [16, used_len-4) == the RTM1
/// signed content (write_image_body in the device codec).
fn write_body(image: &TrustImage, out: &mut Vec<u8>) {
    out.extend_from_slice(&image.store_epoch.to_be_bytes());
    out.extend_from_slice(&image.min_authority_generation.to_be_bytes());
    out.extend_from_slice(&image.network.to_be_bytes());
    out.extend_from_slice(&image.deployment_id.to_be_bytes());
    out.push(image.flags);
    out.push(image.anchors.len() as u8);
    out.push(image.keys.len() as u8);
    out.push(image.revocations.len() as u8);
    out.extend_from_slice(&0_u32.to_be_bytes()); // reserved
    for anchor in &image.anchors {
        out.extend_from_slice(&anchor.root_id.to_be_bytes());
        out.extend_from_slice(&anchor.pubkey);
        out.push(anchor.status as u8);
        out.extend_from_slice(&[0_u8; 7]);
    }
    for key in &image.keys {
        out.extend_from_slice(&key.authority_id.to_be_bytes());
        out.extend_from_slice(&key.generation.to_be_bytes());
        out.push(key.profile);
        out.push(key.role);
        out.push(key.status as u8);
        out.push(key.scope);
        out.extend_from_slice(&key.pubkey);
    }
    for revocation in &image.revocations {
        out.extend_from_slice(&revocation.node_id.to_be_bytes());
        out.extend_from_slice(&revocation.kid_fingerprint);
        out.extend_from_slice(&revocation.revoked_at_epoch.to_be_bytes());
        out.push(revocation.kind);
        out.extend_from_slice(&[0_u8; 3]);
    }
}

// Big-endian cursor reader over a slice — the ByteReader mirror. Reads
// fail ProtocolError on truncation (the device never distinguishes).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return err(Code::ProtocolError, "truncated input");
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// Structural body read (read_image_body): fields, caps, in-entry reserved
/// bytes and enum ranges only — NOT the semantic layer.
fn read_body(reader: &mut Reader<'_>, image: &mut TrustImage) -> Result<()> {
    image.store_epoch = reader.u32()?;
    image.min_authority_generation = reader.u32()?;
    image.network = reader.u64()?;
    image.deployment_id = reader.u64()?;
    image.flags = reader.u8()?;
    let anchor_count = reader.u8()?;
    let key_count = reader.u8()?;
    let revocation_count = reader.u8()?;
    let reserved32 = reader.u32()?;
    if reserved32 != 0
        || (image.flags & !FLAG_MASK) != 0
        || anchor_count as usize > TRUST_ANCHOR_MAX
        || key_count as usize > TRUST_KEY_MAX
        || revocation_count as usize > TRUST_REVOCATION_MAX
    {
        return err(Code::ProtocolError, "trust image head invalid");
    }
    image.anchors.clear();
    for _ in 0..anchor_count {
        let root_id = reader.u64()?;
        let pubkey: [u8; 64] = reader.take(64)?.try_into().expect("64");
        let raw_status = reader.u8()?;
        let reserved = reader.take(7)?;
        if !all_zero(reserved) || !(1..=2).contains(&raw_status) {
            return err(Code::ProtocolError, "trust anchor entry invalid");
        }
        image.anchors.push(TrustAnchor {
            root_id,
            pubkey,
            status: if raw_status == 1 {
                AnchorStatus::Active
            } else {
                AnchorStatus::Disabled
            },
        });
    }
    image.keys.clear();
    for _ in 0..key_count {
        let authority_id = reader.u64()?;
        let generation = reader.u32()?;
        let profile = reader.u8()?;
        let role = reader.u8()?;
        let raw_status = reader.u8()?;
        let scope = reader.u8()?;
        let pubkey: [u8; 64] = reader.take(64)?.try_into().expect("64");
        if profile != 1 || role != 1 || !(1..=4).contains(&raw_status) || scope != 0 {
            return err(Code::ProtocolError, "trust key entry invalid");
        }
        image.keys.push(TrustKeyRecord {
            authority_id,
            generation,
            profile,
            role,
            status: match raw_status {
                1 => KeyStatus::Staged,
                2 => KeyStatus::Active,
                3 => KeyStatus::Retired,
                _ => KeyStatus::Revoked,
            },
            scope,
            pubkey,
        });
    }
    image.revocations.clear();
    for _ in 0..revocation_count {
        let node_id = reader.u64()?;
        let kid_fingerprint: [u8; 32] = reader.take(32)?.try_into().expect("32");
        let revoked_at_epoch = reader.u32()?;
        let kind = reader.u8()?;
        let reserved = reader.take(3)?;
        if !all_zero(reserved) || kind != 1 {
            return err(Code::ProtocolError, "trust revocation entry invalid");
        }
        image.revocations.push(TrustRevocation {
            node_id,
            kid_fingerprint,
            revoked_at_epoch,
            kind,
        });
    }
    Ok(())
}

fn encode_record(image: &TrustImage, seal: u32, used_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(used_len);
    out.extend_from_slice(&TRUST_MAGIC.to_be_bytes());
    out.extend_from_slice(&TRUST_FORMAT.to_be_bytes());
    out.extend_from_slice(&(used_len as u16).to_be_bytes());
    out.extend_from_slice(&TRUST_STORE_SCHEMA_VERSION.to_be_bytes());
    out.extend_from_slice(&seal.to_be_bytes());
    write_body(image, &mut out);
    if out.len() != used_len - 4 {
        return err(Code::InternalError, "trust image size drift");
    }
    let crc = crc32_iso_hdlc(&out[..used_len - 4]);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Semantic validation of a candidate image — the host mirror of
/// `trust_image_validate`: nonzero epoch/network, counts within caps,
/// flags restricted to defined bits, all enum fields in range, unique
/// root_ids and (authority_id, generation) pairs, every pubkey on the
/// P-256 curve, and >=1 ACTIVE anchor so the image can never break the
/// manifest signature chain (§4.5.1 rule 5). Pure function of the image.
pub fn image_validate(image: &TrustImage) -> Result<()> {
    if image.store_epoch == 0 || image.network == 0 {
        return err(Code::InvalidArgument, "trust image epoch/network zero");
    }
    if image.anchors.is_empty()
        || image.anchors.len() > TRUST_ANCHOR_MAX
        || image.keys.len() > TRUST_KEY_MAX
        || image.revocations.len() > TRUST_REVOCATION_MAX
        || (image.flags & !FLAG_MASK) != 0
    {
        return err(Code::InvalidArgument, "trust image counts/flags");
    }
    let mut active_anchor = false;
    for (i, anchor) in image.anchors.iter().enumerate() {
        if anchor.root_id == 0 {
            return err(Code::InvalidArgument, "trust anchor id zero");
        }
        if image.anchors[i + 1..]
            .iter()
            .any(|other| other.root_id == anchor.root_id)
        {
            return err(Code::InvalidArgument, "trust anchor id duplicated");
        }
        if !pubkey_on_curve(&anchor.pubkey) {
            return err(Code::InvalidArgument, "trust anchor key off curve");
        }
        if anchor.status == AnchorStatus::Active {
            active_anchor = true;
        }
    }
    if !active_anchor {
        // An image that leaves zero active anchors can never break its own
        // signature chain — after commit, recovery becomes physical-only
        // by accident (§4.5.1 rule 5).
        return err(Code::InvalidArgument, "trust image no active anchor");
    }
    for (i, key) in image.keys.iter().enumerate() {
        if key.authority_id == 0 || key.authority_id == BROADCAST_NODE_ID || key.generation == 0 {
            return err(Code::InvalidArgument, "trust key identity");
        }
        if key.profile != 1 || key.role != 1 || key.scope != 0 {
            return err(Code::InvalidArgument, "trust key fields");
        }
        if image.keys[i + 1..].iter().any(|other| {
            other.authority_id == key.authority_id && other.generation == key.generation
        }) {
            return err(Code::InvalidArgument, "trust key duplicated");
        }
        if !pubkey_on_curve(&key.pubkey) {
            return err(Code::InvalidArgument, "trust key off curve");
        }
    }
    for revocation in &image.revocations {
        if revocation.node_id == INVALID_NODE_ID
            || revocation.node_id == BROADCAST_NODE_ID
            || revocation.kind != 1
            || all_zero(&revocation.kid_fingerprint)
        {
            return err(Code::InvalidArgument, "trust revocation entry");
        }
    }
    Ok(())
}

/// Encode a complete RLT1 record (head + content + CRC) with `seal` in the
/// seal field — TRUST_SEAL_PENDING while a write is in flight,
/// TRUST_SEAL_COMMITTED for the commit marker. Validates the image
/// semantically first — an invalid image is never encodable, so no path
/// can persist a store that wedges boot validation.
pub fn image_encode(image: &TrustImage, seal: u32) -> Result<Vec<u8>> {
    image_validate(image)?;
    if seal != TRUST_SEAL_PENDING && seal != TRUST_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "trust seal value");
    }
    let used_len = image_encoded_size(image)
        .filter(|&len| len <= TRUST_STORE_SLOT_BYTES)
        .ok_or(Error::new(Code::InvalidArgument, "trust image oversize"))?;
    encode_record(image, seal, used_len)
}

/// The RTM1 signed content — RLT1 bytes [16, used_len-4). Shared with the
/// record codec so verification, persistence and catch-up share one truth.
/// Structural encode only (matches `trust_image_body_encode`: no semantic
/// validation — callers that need it run `image_validate` first).
pub fn image_body_encode(image: &TrustImage) -> Result<Vec<u8>> {
    let used_len = image_encoded_size(image)
        .filter(|&len| len - 20 <= TRUST_IMAGE_CONTENT_MAX)
        .ok_or(Error::new(Code::InvalidArgument, "trust image oversize"))?;
    let mut out = Vec::with_capacity(used_len - 20);
    write_body(image, &mut out);
    Ok(out)
}

/// Structural body decode (trust_image_body_decode): fields, caps, exact
/// length; `image_validate` applies the semantic layer.
pub fn image_body_decode(content: &[u8]) -> Result<TrustImage> {
    // The content head alone is 32 bytes; whether the image must carry
    // >=1 active anchor is a semantic rule, not a codec bound.
    if content.len() < 32 || content.len() > TRUST_IMAGE_CONTENT_MAX {
        return err(Code::ProtocolError, "trust content bounds");
    }
    let mut image = TrustImage::default();
    let mut reader = Reader::new(content);
    read_body(&mut reader, &mut image)?;
    // Entry tables must be exactly sized: no trailing bytes (§4.5.1 rule 2).
    if reader.remaining() != 0 {
        return err(Code::ProtocolError, "trust content trailing");
    }
    Ok(image)
}

/// Decode and fully validate a committed RLT1 record (magic, format,
/// used_len, seal == committed, counts/reserved/enum structure, CRC,
/// schema, image_validate) — `trust_image_decode`. Tolerates a buffer
/// longer than used_len (the slot tail reads back erased).
pub fn image_decode(record: &[u8]) -> Result<TrustImage> {
    if record.len() < TRUST_IMAGE_HEADER_SIZE + 4 || record.len() > TRUST_STORE_SLOT_BYTES {
        return err(Code::ProtocolError, "trust record bounds");
    }
    let mut reader = Reader::new(record);
    let magic = reader.u32()?;
    let format = reader.u16()?;
    let used_len = usize::from(reader.u16()?);
    let schema = reader.u32()?;
    let seal = reader.u32()?;
    if magic != TRUST_MAGIC
        || format != TRUST_FORMAT
        || used_len < TRUST_IMAGE_HEADER_SIZE + 4
        || used_len > record.len()
    {
        return err(Code::ProtocolError, "trust record head");
    }
    if seal != TRUST_SEAL_COMMITTED {
        return err(Code::ProtocolError, "trust record uncommitted");
    }
    let mut image = TrustImage::default();
    read_body(&mut reader, &mut image)?;
    let crc = reader.u32()?;
    if reader.pos != used_len {
        return err(Code::ProtocolError, "trust record length");
    }
    if crc32_iso_hdlc(&record[..used_len - 4]) != crc {
        return err(Code::IntegrityError, "trust record crc");
    }
    if schema != TRUST_STORE_SCHEMA_VERSION {
        return err(Code::Unsupported, "trust record schema");
    }
    image_validate(&image)?;
    Ok(image)
}

/// SHA-256 over a committed RLT1 record's bytes [0, used_len) — the
/// image_fingerprint the TrustStatus reply exports (§4.3.4). Input must be
/// a plausible committed record (bounds only, like the device function).
pub fn image_fingerprint(record: &[u8]) -> Result<[u8; 32]> {
    if record.len() < TRUST_IMAGE_HEADER_SIZE + 4 || record.len() > TRUST_STORE_SLOT_BYTES {
        return err(Code::InvalidArgument, "trust fingerprint input");
    }
    Ok(sha256(record))
}

/// Find an anchor by manifest kid (root_id); the store-side lookup.
pub fn find_anchor(image: &TrustImage, root_id: u64) -> Option<&TrustAnchor> {
    image.anchors.iter().find(|a| a.root_id == root_id)
}

/// Exact (authority_id, generation) key lookup — the §4.6.2 TrustView
/// primitive. Staged/retired/revoked records ARE returned; the caller
/// enforces the status policy.
pub fn find_key(image: &TrustImage, authority_id: u64, generation: u32) -> Option<&TrustKeyRecord> {
    image
        .keys
        .iter()
        .find(|k| k.authority_id == authority_id && k.generation == generation)
}

/// Revocation check on the credential fingerprint (kind DeviceCredential).
pub fn is_credential_revoked(image: &TrustImage, kid_fingerprint: &[u8; 32]) -> bool {
    image
        .revocations
        .iter()
        .any(|r| r.kind == 1 && &r.kid_fingerprint == kid_fingerprint)
}
