//! `RLC1` `DeviceCredentialRecord` codec — byte-for-byte mirror of
//! `components/routeloom/src/device_credential.cpp`
//! (04-provisioning-lifecycle.md §4.3.2). The record binds one node's
//! identity: full-u64 `network` (deployment generation in the upper
//! bits, §4.8), `node_id`, `generation_base_session`, the P-256 RPK
//! (public half + location-tagged private material), the kid fingerprint
//! and the authority-issued MembershipGrant.
//!
//! Layout (all integers big-endian; ≤1024-byte slot):
//! ```text
//!  0   u32  magic "RLC1" (0x524C4331)
//!  4   u16  format = 1
//!  6   u16  used_len (bytes incl. CRC)
//!  8   u32  schema_version = 1
//! 12   u32  seal (0 pending / 0xC0ED1CE5 committed)
//! 16   u64  network | u64 node_id
//! 32   u32  generation_base_session
//! 36   u8 key_location | u8 cred_status | u16 grant_len
//! 40   32B  kid = SHA-256(canonical COSE_Key(pubkey))
//! 72   64B  pubkey X||Y
//! 136  32B  private_key (location 1) | opaque handle (location >=2) | zero
//! 168  grant bytes (<=256)
//! len-4 u32  crc32_iso_hdlc over [0, used_len-4)
//! ```
//! RLC1 carries no ordinal: a commit writes the SAME record to both slots,
//! so two surviving valid records must be byte-identical.

use crate::crc32::crc32_iso_hdlc;
use crate::image::pubkey_on_curve;
use crate::sha256::sha256;
use crate::signer::pubkey_from_secret;
use crate::{cbor, err, Code, Error, Result, BROADCAST_NODE_ID, INVALID_NODE_ID};

pub const CRED_MAGIC: u32 = 0x524C_4331; // "RLC1"
pub const CRED_FORMAT: u16 = 1;
pub const CRED_SEAL_PENDING: u32 = 0;
pub const CRED_SEAL_COMMITTED: u32 = 0xC0ED_1CE5; // §4.3.2

pub const CREDENTIAL_SLOTS: usize = 2;
pub const CREDENTIAL_SLOT_BYTES: usize = 1024;
pub const CREDENTIAL_GRANT_MAX: usize = 256;
pub const CREDENTIAL_HEADER_SIZE: usize = 40;
pub const CREDENTIAL_FIXED_BODY: usize = 128; // kid 32 + pubkey 64 + key 32
/// 40 + 128 + grant_len + 4; max 428 bytes, inside the 1024 slot bound.
pub const CREDENTIAL_RECORD_MAX: usize = 428;
pub const CREDENTIAL_SCHEMA_VERSION: u32 = 1;
pub const CREDENTIAL_KEY_MATERIAL_SIZE: usize = 32;
pub const CREDENTIAL_PUBKEY_SIZE: usize = 64;
const CRED_MIN_RECORD: usize = CREDENTIAL_HEADER_SIZE + CREDENTIAL_FIXED_BODY + 4;

/// §4.8 u16 epoch-window bound: when (session - base) reaches 0xFFF0 the
/// next boots would wrap the wire epoch into already-floored values, so
/// bring-up wedges with RecoveryRequired instead of reusing epoch 1.
pub const CREDENTIAL_EPOCH_WINDOW_MAX: u32 = 0xFFF0;

/// Canonical public COSE_Key byte length: a5 map(5) + heads + x + y.
/// a5 01 02 | 03 26 | 20 01 | 21 58 20 <x:32> | 22 58 20 <y:32> = 77 B.
pub const CREDENTIAL_COSE_KEY_SIZE: usize = 77;

/// Where the private half lives (§4.3.2 `key_location`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyLocation {
    /// No private key on device (dev/zero material).
    #[default]
    None = 0,
    /// Private scalar in the record; consistency-checked.
    NvsPlaintext = 1,
    /// `key_material` is an opaque handle (eFuse/DS-bound).
    EfuseDsBound = 2,
    /// `key_material` is an opaque handle (secure element).
    SecureElement = 3,
}

impl KeyLocation {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::NvsPlaintext,
            2 => Self::EfuseDsBound,
            3 => Self::SecureElement,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum CredStatus {
    #[default]
    PendingRegistration = 1,
    Active = 2,
    /// Sticky operator state, not a wire verdict (§4.3.2).
    SuspendedLocal = 3,
}

impl CredStatus {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::PendingRegistration,
            2 => Self::Active,
            3 => Self::SuspendedLocal,
            _ => return None,
        })
    }
}

/// The semantic content of one RLC1 record (post-head fields).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCredential {
    /// FULL NetworkId incl. the §4.8 deployment generation.
    pub network: u64,
    pub node_id: u64,
    /// `rlboot` session at which the current generation took effect.
    pub generation_base_session: u32,
    pub key_location: KeyLocation,
    pub cred_status: CredStatus,
    /// SHA-256 over the canonical COSE_Key — never the private half.
    pub kid: [u8; 32],
    /// X || Y, no SEC1 prefix.
    pub pubkey: [u8; 64],
    /// Location 1: the P-256 private scalar; >=2: opaque key handle;
    /// 0: zero-filled.
    pub key_material: [u8; 32],
    pub grant: Vec<u8>,
}

// [u8; 64] has no std Default impl; the zeroed record is the honest
// "empty" image the decode path builds up field by field.
impl Default for DeviceCredential {
    fn default() -> Self {
        Self {
            network: 0,
            node_id: INVALID_NODE_ID,
            generation_base_session: 0,
            key_location: KeyLocation::None,
            cred_status: CredStatus::PendingRegistration,
            kid: [0; 32],
            pubkey: [0; 64],
            key_material: [0; 32],
            grant: Vec::new(),
        }
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Canonical public COSE_Key for the kid computation (deterministic CBOR,
/// host-security §3): {1:2 (kty EC2), 3:-7 (alg ES256), -1:1 (crv P-256),
/// -2:x, -3:y} — 77 bytes. `pubkey` is the 64-byte X||Y encoding. Distinct
/// from the manifest envelope's alg: ESP256 (-9) is the envelope profile;
/// the credential COSE_Key's `alg` label is ES256 (-7).
pub fn credential_cose_key_encode(pubkey: &[u8; 64]) -> [u8; CREDENTIAL_COSE_KEY_SIZE] {
    let mut out = [0_u8; CREDENTIAL_COSE_KEY_SIZE];
    // a5 01 02 (map5 kty=EC2) | 03 26 (alg=-7 ES256) | 20 01 (crv=P-256)
    // | 21 58 20 <x:32> | 22 58 20 <y:32>
    out[..10].copy_from_slice(&[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out[10..42].copy_from_slice(&pubkey[..32]);
    out[42..45].copy_from_slice(&[0x22, 0x58, 0x20]);
    out[45..77].copy_from_slice(&pubkey[32..]);
    out
}

/// kid = SHA-256 over the 77-byte canonical COSE_Key — the fingerprint the
/// revocation set names (kind DeviceCredential).
pub fn credential_kid(pubkey: &[u8; 64]) -> [u8; 32] {
    sha256(&credential_cose_key_encode(pubkey))
}

/// The fields the §4.3.2 boot check compares against the record, pulled out
/// of the MembershipGrant's signed payload (host-security §3:
/// `[1, network_u32, node_u64, kid_bstr32, role_bits_u32,
///   authority_generation_u64, membership_revision_u64, not_before_u64,
///   not_after_u64]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantFields {
    /// The grant names the wire-visible LOW 32 bits of the full NetworkId.
    pub network_low32: u32,
    pub node_id: u64,
    pub kid: [u8; 32],
}

/// Parse the grant's restricted COSE_Sign1 envelope far enough to reach the
/// signed payload: tag 18, array(4), protected bstr, empty unprotected map,
/// payload bstr, 64-byte signature bstr, no trailing data. The signature
/// itself is NOT verified here — the boot check is field consistency, and
/// grant verification belongs to the membership workstream that owns the
/// signing-key resolution.
fn grant_envelope_payload(grant: &[u8]) -> Result<&[u8]> {
    if grant.len() < 8 || grant.len() > CREDENTIAL_GRANT_MAX {
        return err(Code::ProtocolError, "grant size");
    }
    let mut pos = 0;
    cbor::expect_u8(grant, &mut pos, 0xD2, "grant tag18")?;
    cbor::expect_u8(grant, &mut pos, 0x84, "grant array4")?;
    let protected_bstr = cbor::read_bstr(grant, &mut pos, "grant protected")?;
    cbor::expect_u8(grant, &mut pos, 0xA0, "grant unprotected")?;
    let payload = cbor::read_bstr(grant, &mut pos, "grant payload")?;
    let signature = cbor::read_bstr(grant, &mut pos, "grant signature")?;
    if protected_bstr.is_empty()
        || payload.is_empty()
        || signature.len() != 64
        || pos != grant.len()
    {
        return err(Code::ProtocolError, "grant envelope shape");
    }
    Ok(payload)
}

/// Parse a MembershipGrant envelope + signed payload and extract the fields
/// the RLC1 consistency check compares (network/node/kid). Field
/// consistency ONLY — the grant's COSE signature is not verified here (no
/// authority key resolution exists yet; pending the membership workstream).
pub fn grant_fields_parse(grant: &[u8]) -> Result<GrantFields> {
    let payload = grant_envelope_payload(grant)?;
    let mut pos = 0;
    cbor::expect_u8(payload, &mut pos, 0x89, "grant payload array9")?;
    let version = cbor::read_uint(payload, &mut pos, "grant version")?;
    let network = cbor::read_uint(payload, &mut pos, "grant network")?;
    let node = cbor::read_uint(payload, &mut pos, "grant node")?;
    let kid = cbor::read_bstr(payload, &mut pos, "grant kid")?;
    let role_bits = cbor::read_uint(payload, &mut pos, "grant roles")?;
    let _generation = cbor::read_uint(payload, &mut pos, "grant generation")?;
    let _revision = cbor::read_uint(payload, &mut pos, "grant revision")?;
    let _not_before = cbor::read_uint(payload, &mut pos, "grant not_before")?;
    let _not_after = cbor::read_uint(payload, &mut pos, "grant not_after")?;
    if pos != payload.len()
        || version != 1
        || network > 0xFFFF_FFFF
        || role_bits > 0xFFFF_FFFF
        || kid.len() != 32
    {
        return err(Code::ProtocolError, "grant payload fields");
    }
    let mut fields = GrantFields {
        network_low32: network as u32,
        node_id: node,
        kid: [0_u8; 32],
    };
    fields.kid.copy_from_slice(kid);
    Ok(fields)
}

/// Record-level consistency checks (§4.3.2 boot checks):
///  - fields in range; nonzero network/node_id;
///  - `kid == SHA-256(canonical COSE_Key(pubkey))` and pubkey on-curve;
///  - `key_location` 0 → key_material all-zero; 1 → the private scalar
///    reproduces the public half; >=2 → opaque handle, no local check;
///  - when grant bytes are present, the grant payload must parse and its
///    network-low32/node/kid must equal the record's.
///
/// Any mismatch is corruption — never a cue to re-derive a credential.
pub fn credential_validate(credential: &DeviceCredential) -> Result<()> {
    if credential.network == 0
        || credential.node_id == INVALID_NODE_ID
        || credential.node_id == BROADCAST_NODE_ID
    {
        return err(Code::InvalidArgument, "credential identity");
    }
    // Enum values arrive typed in Rust; the decode path constructs them
    // through from_u8 so out-of-range bytes are already refused there.
    if !pubkey_on_curve(&credential.pubkey) {
        return err(Code::InvalidArgument, "credential pubkey off curve");
    }
    if credential_kid(&credential.pubkey) != credential.kid {
        return err(Code::IntegrityError, "credential kid mismatch");
    }
    match credential.key_location {
        KeyLocation::None => {
            if !all_zero(&credential.key_material) {
                return err(Code::InvalidArgument, "credential key residue");
            }
        }
        KeyLocation::NvsPlaintext => {
            let computed = pubkey_from_secret(&credential.key_material);
            if computed.as_ref() != Some(&credential.pubkey) {
                // Corruption, never a cue to "re-derive" (§4.3.2).
                return err(Code::IntegrityError, "credential keypair mismatch");
            }
        }
        _ => {
            // eFuse/DS-bound and secure-element locations carry an opaque
            // handle the host cannot interpret — no local check exists.
        }
    }
    if !credential.grant.is_empty() {
        let fields = grant_fields_parse(&credential.grant)?;
        // The grant's network_u32 names the wire-visible low32 of the full
        // NetworkId (§4.8); node and kid bind the whole record.
        if fields.network_low32 != (credential.network & 0xFFFF_FFFF) as u32
            || fields.node_id != credential.node_id
            || fields.kid != credential.kid
        {
            return err(Code::IntegrityError, "credential grant mismatch");
        }
    }
    Ok(())
}

fn encode_record(credential: &DeviceCredential, seal: u32, used_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(used_len);
    out.extend_from_slice(&CRED_MAGIC.to_be_bytes());
    out.extend_from_slice(&CRED_FORMAT.to_be_bytes());
    out.extend_from_slice(&(used_len as u16).to_be_bytes());
    out.extend_from_slice(&CREDENTIAL_SCHEMA_VERSION.to_be_bytes());
    out.extend_from_slice(&seal.to_be_bytes());
    out.extend_from_slice(&credential.network.to_be_bytes());
    out.extend_from_slice(&credential.node_id.to_be_bytes());
    out.extend_from_slice(&credential.generation_base_session.to_be_bytes());
    out.push(credential.key_location as u8);
    out.push(credential.cred_status as u8);
    out.extend_from_slice(&(credential.grant.len() as u16).to_be_bytes());
    out.extend_from_slice(&credential.kid);
    out.extend_from_slice(&credential.pubkey);
    out.extend_from_slice(&credential.key_material);
    out.extend_from_slice(&credential.grant);
    if out.len() != used_len - 4 {
        return err(Code::InternalError, "credential size drift");
    }
    let crc = crc32_iso_hdlc(&out[..used_len - 4]);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Encode a complete RLC1 record (head + body + CRC) with `seal` in the
/// seal field — CRED_SEAL_PENDING while a write is in flight,
/// CRED_SEAL_COMMITTED for the commit marker. Validates the credential
/// first so no path persists a record boot would reject. Returns the
/// used_len bytes; a slot image pads the tail with 0xFF.
pub fn credential_record_encode(credential: &DeviceCredential, seal: u32) -> Result<Vec<u8>> {
    credential_validate(credential)?;
    if seal != CRED_SEAL_PENDING && seal != CRED_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "credential seal value");
    }
    let used_len = CREDENTIAL_HEADER_SIZE + CREDENTIAL_FIXED_BODY + credential.grant.len() + 4;
    if used_len > CREDENTIAL_SLOT_BYTES || credential.grant.len() > CREDENTIAL_GRANT_MAX {
        return err(Code::InvalidArgument, "credential oversize");
    }
    encode_record(credential, seal, used_len)
}

// Big-endian cursor reader over a slice — the ByteReader mirror (same
// shape as image::Reader; file-local like the device's per-TU helpers).
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
}

/// Decode and fully validate a committed RLC1 record (magic, format,
/// used_len, seal == committed, grant_len consistency, CRC, schema, then
/// `credential_validate`) — `credential_record_decode`. Tolerates a buffer
/// longer than used_len (the slot tail reads back erased).
pub fn credential_record_decode(record: &[u8]) -> Result<DeviceCredential> {
    if record.len() < CRED_MIN_RECORD || record.len() > CREDENTIAL_SLOT_BYTES {
        return err(Code::ProtocolError, "credential record bounds");
    }
    let mut reader = Reader::new(record);
    let magic = reader.u32()?;
    let format = reader.u16()?;
    let used_len = usize::from(reader.u16()?);
    let schema = reader.u32()?;
    let seal = reader.u32()?;
    if magic != CRED_MAGIC
        || format != CRED_FORMAT
        || used_len < CRED_MIN_RECORD
        || used_len > record.len()
    {
        return err(Code::ProtocolError, "credential record head");
    }
    if seal != CRED_SEAL_COMMITTED {
        return err(Code::ProtocolError, "credential uncommitted");
    }
    let mut credential = DeviceCredential {
        network: reader.u64()?,
        node_id: reader.u64()?,
        generation_base_session: reader.u32()?,
        ..DeviceCredential::default()
    };
    let key_location = reader.u8()?;
    let cred_status = reader.u8()?;
    let grant_len = usize::from(reader.u16()?);
    if grant_len > CREDENTIAL_GRANT_MAX
        || CREDENTIAL_HEADER_SIZE + CREDENTIAL_FIXED_BODY + grant_len + 4 != used_len
    {
        return err(Code::ProtocolError, "credential record length");
    }
    // Enum range is structural on this codec path: out-of-range bytes are
    // corruption, which credential_validate's field-range rule mirrors.
    credential.key_location = KeyLocation::from_u8(key_location)
        .ok_or(Error::new(Code::InvalidArgument, "credential fields"))?;
    credential.cred_status = CredStatus::from_u8(cred_status)
        .ok_or(Error::new(Code::InvalidArgument, "credential fields"))?;
    credential.kid.copy_from_slice(reader.take(32)?);
    credential.pubkey.copy_from_slice(reader.take(64)?);
    credential.key_material.copy_from_slice(reader.take(32)?);
    credential.grant = reader.take(grant_len)?.to_vec();
    let crc = reader.u32()?;
    if reader.pos != used_len {
        return err(Code::ProtocolError, "credential record truncated");
    }
    if crc32_iso_hdlc(&record[..used_len - 4]) != crc {
        return err(Code::IntegrityError, "credential record crc");
    }
    if schema != CREDENTIAL_SCHEMA_VERSION {
        return err(Code::Unsupported, "credential record schema");
    }
    credential_validate(&credential)?;
    Ok(credential)
}

/// §4.8 epoch window: wire epochs derive as `((session - base - 1) %
/// 0xFFFF) + 1` where `base` is `generation_base_session` — the existing
/// (session-1) mapping with the window origin moved. `session` must be
/// strictly greater than `base` (the cutover session itself predates the
/// window).
///
/// The u16 space is finite: when (session - base) reaches the 0xFFF0
/// threshold the next boots would walk into the wrap that reuses epoch 1
/// under peer floors that can never accept it. Instead of silently
/// wrapping, the helper fails with RecoveryRequired — the design's
/// REPROVISION_REQUIRED wedge: refuse network bring-up, leave a
/// diagnostic, recover via a deployment-generation cutover (or literal
/// re-provisioning on the dev bench).
pub fn credential_epoch_for_session(session: u32, generation_base_session: u32) -> Result<u16> {
    if session == 0 || session <= generation_base_session {
        // A session at or before the generation base predates the window
        // the base defines — there is no epoch to derive.
        return err(Code::InvalidArgument, "epoch session before base");
    }
    let elapsed = session - generation_base_session;
    if elapsed >= CREDENTIAL_EPOCH_WINDOW_MAX {
        return err(
            Code::RecoveryRequired,
            "epoch window exhausted; re-provision required",
        );
    }
    Ok(((elapsed - 1) % 0xFFFF) as u16 + 1)
}

/// A field-consistent MembershipGrant in the restricted envelope the RLC1
/// boot check parses — the host mirror of `test_grant` in
/// `tests/cpp/test_provisioning.hpp`. The signature bytes are zeros: grant
/// signature verification belongs to the membership workstream, not this
/// codec, so the fixture emits a shape-valid envelope only. Payload:
/// `[1, network_low32, node_id, kid bstr32, role_bits, generation,
///   revision, not_before, not_after]`.
#[allow(clippy::too_many_arguments)]
pub fn grant_fixture(
    network: u64,
    node_id: u64,
    kid: &[u8; 32],
    role_bits: u64,
    generation: u64,
    revision: u64,
    not_before: u64,
    not_after: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);
    payload.push(0x89); // array(9)
    cbor::write_uint(&mut payload, 1); // version
    cbor::write_uint(&mut payload, network & 0xFFFF_FFFF); // low32
    cbor::write_uint(&mut payload, node_id);
    cbor::write_bstr(&mut payload, kid);
    cbor::write_uint(&mut payload, role_bits);
    cbor::write_uint(&mut payload, generation);
    cbor::write_uint(&mut payload, revision);
    cbor::write_uint(&mut payload, not_before);
    cbor::write_uint(&mut payload, not_after);

    let mut out = Vec::with_capacity(payload.len() + 90);
    out.push(0xD2); // tag 18
    out.push(0x84); // array(4)
    cbor::write_bstr(&mut out, &[0xA0]); // nonempty protected per profile
    out.push(0xA0); // empty unprotected map
    cbor::write_bstr(&mut out, &payload);
    cbor::write_bstr(&mut out, &[0_u8; 64]); // signature placeholder
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::test_keypair;

    fn test_credential(network: u64, node: u64, keys: &([u8; 32], [u8; 64])) -> DeviceCredential {
        let pubkey = keys.1;
        let kid = credential_kid(&pubkey);
        let mut credential = DeviceCredential {
            network,
            node_id: node,
            generation_base_session: 500,
            key_location: KeyLocation::NvsPlaintext,
            cred_status: CredStatus::Active,
            kid,
            pubkey,
            key_material: keys.0,
            grant: Vec::new(),
        };
        credential.grant = grant_fixture(network, node, &kid, 3, 7, 11, 1000, 2000);
        credential
    }

    #[test]
    fn cose_key_layout() {
        let (_, pub_a) = test_keypair(0x55);
        let key = credential_cose_key_encode(&pub_a);
        assert_eq!(key.len(), 77);
        assert_eq!(
            &key[..10],
            &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&key[10..42], &pub_a[..32]);
        assert_eq!(&key[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&key[45..77], &pub_a[32..]);
        assert_eq!(credential_kid(&pub_a), sha256(&key));
    }

    #[test]
    fn credential_validate_paths() {
        let keys_a = test_keypair(0x55);
        let keys_b = test_keypair(0x66);
        let credential = test_credential(7, 0xC3, &keys_a);
        assert!(credential_validate(&credential).is_ok());

        let mut bad = credential.clone();
        bad.network = 0;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::InvalidArgument
        );
        let mut bad = credential.clone();
        bad.node_id = INVALID_NODE_ID;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::InvalidArgument
        );
        let mut bad = credential.clone();
        bad.node_id = BROADCAST_NODE_ID;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::InvalidArgument
        );

        // kid mismatch.
        let mut bad = credential.clone();
        bad.kid[0] ^= 0xFF;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::IntegrityError
        );
        // Off-curve pubkey.
        let mut bad = credential.clone();
        bad.pubkey = [0x55; 64];
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::InvalidArgument
        );
        // A different node's on-curve pubkey mismatches the recorded kid.
        let mut bad = credential.clone();
        bad.pubkey = keys_b.1;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::IntegrityError
        );
    }

    #[test]
    fn key_location_rules() {
        let keys_a = test_keypair(0x55);
        let keys_b = test_keypair(0x66);
        // Location 0 requires all-zero material.
        let mut credential = test_credential(7, 0xC3, &keys_a);
        credential.key_location = KeyLocation::None;
        credential.key_material = [0; 32];
        assert!(credential_validate(&credential).is_ok());
        credential.key_material[3] = 1;
        assert_eq!(
            credential_validate(&credential).unwrap_err().code,
            Code::InvalidArgument
        );
        // Location 1: private scalar must reproduce the public half.
        let mut credential = test_credential(7, 0xC3, &keys_a);
        assert!(credential_validate(&credential).is_ok());
        credential.key_material = keys_b.0;
        assert_eq!(
            credential_validate(&credential).unwrap_err().code,
            Code::IntegrityError
        );
        // Locations >=2: opaque handle, any bytes acceptable.
        for location in [KeyLocation::EfuseDsBound, KeyLocation::SecureElement] {
            let mut credential = test_credential(7, 0xC3, &keys_a);
            credential.key_location = location;
            credential.key_material = [0x99; 32];
            assert!(credential_validate(&credential).is_ok());
        }
    }

    #[test]
    fn grant_consistency() {
        let keys_a = test_keypair(0x55);
        let keys_b = test_keypair(0x66);
        let credential = test_credential(7, 0xC3, &keys_a);
        assert!(credential_validate(&credential).is_ok());

        // Grant naming another kid / another node / another low32 fails.
        let mut bad = credential.clone();
        bad.grant = grant_fixture(7, 0xC3, &credential_kid(&keys_b.1), 3, 7, 11, 1000, 2000);
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::IntegrityError
        );
        let mut bad = credential.clone();
        bad.grant = grant_fixture(7, 0x99, &credential.kid, 3, 7, 11, 1000, 2000);
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::IntegrityError
        );
        let mut bad = credential.clone();
        bad.grant = grant_fixture(8, 0xC3, &credential.kid, 3, 7, 11, 1000, 2000);
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::IntegrityError
        );
        // Upper deployment-generation bits are not part of the grant check.
        let mut upper = credential.clone();
        upper.network = (5_u64 << 32) | 7;
        assert!(credential_validate(&upper).is_ok());
        // Malformed grant bytes are a parse error, not a mismatch.
        let mut bad = credential.clone();
        bad.grant[0] = 0xD3;
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::ProtocolError
        );
        let mut bad = credential.clone();
        bad.grant.truncate(4);
        assert_eq!(
            credential_validate(&bad).unwrap_err().code,
            Code::ProtocolError
        );
        // No grant at all is a legal pre-registration state.
        let mut bare = credential.clone();
        bare.grant.clear();
        assert!(credential_validate(&bare).is_ok());
    }

    #[test]
    fn record_roundtrip() {
        let keys_a = test_keypair(0x55);
        let credential = test_credential(7, 0xC3, &keys_a);
        let record = credential_record_encode(&credential, CRED_SEAL_COMMITTED).unwrap();
        assert_eq!(
            record.len(),
            CREDENTIAL_HEADER_SIZE + CREDENTIAL_FIXED_BODY + credential.grant.len() + 4
        );
        assert_eq!(&record[..4], b"RLC1");
        assert_eq!(record[11], 1); // schema low byte
        assert!(record[12] == 0xC0 && record[15] == 0xE5); // seal 0xC0ED1CE5
        let decoded = credential_record_decode(&record).unwrap();
        assert_eq!(decoded, credential);

        // Grant-free record: minimum size.
        let mut bare = credential.clone();
        bare.grant.clear();
        let bare_record = credential_record_encode(&bare, CRED_SEAL_COMMITTED).unwrap();
        assert_eq!(
            bare_record.len(),
            CREDENTIAL_HEADER_SIZE + CREDENTIAL_FIXED_BODY + 4
        );
        assert_eq!(credential_record_decode(&bare_record).unwrap(), bare);

        // Pending seal encodes but never decodes as committed.
        let pending = credential_record_encode(&credential, CRED_SEAL_PENDING).unwrap();
        assert_eq!(
            credential_record_decode(&pending).unwrap_err().code,
            Code::ProtocolError
        );
        // Unknown seal refused at encode; oversize refused.
        assert_eq!(
            credential_record_encode(&credential, 0x7777_7777)
                .unwrap_err()
                .code,
            Code::InvalidArgument
        );
        // An oversize grant fails grant validation first — the device's
        // grant_fields_parse also reports ProtocolError for grant > 256 B.
        let mut huge = credential.clone();
        huge.grant = vec![0_u8; CREDENTIAL_GRANT_MAX + 1];
        assert_eq!(
            credential_record_encode(&huge, CRED_SEAL_COMMITTED)
                .unwrap_err()
                .code,
            Code::ProtocolError
        );
        // A 1024-byte slot image with an erased tail decodes identically.
        let mut slot = vec![0xFF_u8; CREDENTIAL_SLOT_BYTES];
        slot[..record.len()].copy_from_slice(&record);
        assert_eq!(credential_record_decode(&slot).unwrap(), credential);
    }

    #[test]
    fn epoch_window() {
        // base = 500 (the fixture's generation_base_session).
        assert_eq!(
            credential_epoch_for_session(500, 500).unwrap_err().code,
            Code::InvalidArgument
        );
        assert_eq!(credential_epoch_for_session(501, 500).unwrap(), 1);
        assert_eq!(
            credential_epoch_for_session(0, 500).unwrap_err().code,
            Code::InvalidArgument
        );
        // The last usable session before the wedge: elapsed 0xFFEF → epoch 65519.
        assert_eq!(
            credential_epoch_for_session(500 + 0xFFEF, 500).unwrap(),
            0xFFEF
        );
        assert_eq!(
            credential_epoch_for_session(500 + 0xFFF0, 500)
                .unwrap_err()
                .code,
            Code::RecoveryRequired
        );
        // u16 wrap point inside the window maps modularly — by design the
        // wedge lands BEFORE wraparound can ever matter: elapsed 0xFFFF
        // already exceeds the 0xFFF0 threshold, so the % path is unreachable
        // in production. Verify the arithmetic anyway: elapsed 0x10000 < ...
        // (unreachable — kept as documentation of the mapping).
        assert_eq!(
            credential_epoch_for_session(500 + 0xFFF1, 500)
                .unwrap_err()
                .code,
            Code::RecoveryRequired
        );
    }
}
