//! SDK v1 (G-SEC) certificate and record codecs — the host mirror of
//! `components/routeloom/src/{rlcw1,sdkv1_records}.cpp`
//! (docs/design/sdk-v1/08 P1-2/P1-3). The office tooling (DevCert, RLI1,
//! P7-1) and the Site Authority (SiteCert/MemberCert issue, RRS1 publish,
//! P3-3/P6-1) build on these; `protocol/sdkv1-golden/` pins every byte
//! against the independent generator `tools/gen_sdkv1_vectors.py` and the
//! C++ codecs.
//!
//! - [`cert`] — RLCW1 DevCert / SiteCert / MemberCert (CWT in a restricted
//!   ES256 COSE_Sign1), strict decode, RFC 6979 issue, verify.
//! - [`identity`] — RLI1 device identity record.
//! - [`site`] — RLS1 site membership record (with the A/B `commit_seq`).
//! - [`revocation`] — RRS1 payload, AAD, Sign1 object, storage record.
//! - [`resume`] — RLP1 resumption-cache slot.
//! - [`resume2`] — RLP2 resumption-cache slot (64-use ceiling, P4).
//! - [`local_revocation`] — RLV1 durable local-removal evidence (P4).
//!
//! Office tooling (P7-1, 07 §6):
//! - [`devca`] — `DeviceCaSigner` custody seam, dev `FileDeviceCaSigner`,
//!   DevCert issue (possession-proven keys only) and verification.
//! - [`pop`] — device-key proof of possession (challenge, sign, verify).
//! - [`office`] — RLI1 assembly for injected keys, the identity bundle for
//!   device-generated keys, inventory lines.
//! - [`rlsec`] — the manufactured `rlsec` NVS set (`rlident` twin pair) and
//!   its `nvs_partition_gen` CSV.
//!
//! Site tooling (P7-2, 07 §6):
//! - [`siteca`] — `SiteCaSigner` custody seam, dev `FileSiteCaSigner`, and
//!   SiteCert issue (HQ, when the site PC is set up) and verification.
//!
//! The device-side dual-slot stores are C++ only; the host needs the
//! byte formats, not the power-cut state machine.

pub mod cert;
pub mod devca;
pub mod identity;
pub mod local_revocation;
pub mod office;
pub mod pop;
pub mod resume;
pub mod resume2;
pub mod revocation;
pub mod rlsec;
pub mod site;
pub mod siteca;

use crate::crc32::crc32_iso_hdlc;
use crate::sha256::sha256;
use crate::signer::{signature_range_check, RootSigner};
use crate::{err, Code, Error, Result};

/// Shared sealed-record head values.
pub const SEAL_PENDING: u32 = 0;
pub const RECORD_FORMAT: u16 = 1;
pub const RECORD_SCHEMA: u32 = 1;
pub const SEALED_HEAD_SIZE: usize = 16;
pub const SEQUENCED_HEAD_SIZE: usize = 20;

/// `{1: -7}` — the only protected header the profile admits.
pub const PROTECTED_ES256: [u8; 3] = [0xA1, 0x01, 0x26];
const SIGN1_HEAD: [u8; 7] = [0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0];

pub(crate) fn id_valid(id: u64) -> bool {
    id != 0 && id != u64::MAX
}

/// Big-endian readers over a slice with a moving cursor. Every read is
/// bounds-checked; a short buffer is a ProtocolError.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub(crate) fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.pos + count > self.data.len() {
            return err(Code::ProtocolError, "record truncated");
        }
        let out = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn zeros(&mut self, count: usize, what: &'static str) -> Result<()> {
        if self.bytes(count)?.iter().any(|&b| b != 0) {
            return err(Code::ProtocolError, what);
        }
        Ok(())
    }
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// Sealed head: magic | format | used_len | schema | seal. `used_len` is
/// patched by [`finish_record`].
pub(crate) fn begin_record(magic: u32, seal: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(&magic.to_be_bytes());
    out.extend_from_slice(&RECORD_FORMAT.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&RECORD_SCHEMA.to_be_bytes());
    out.extend_from_slice(&seal.to_be_bytes());
    out
}

/// Patch used_len and append the CRC-32/ISO-HDLC tail.
pub(crate) fn finish_record(mut out: Vec<u8>) -> Vec<u8> {
    let used_len = (out.len() + 4) as u16;
    out[6..8].copy_from_slice(&used_len.to_be_bytes());
    let crc = crc32_iso_hdlc(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

/// Strict committed-record head check (same order and verdicts as the
/// device `read_head`): head fields, exact length, committed seal, CRC,
/// then schema (Unsupported). Returns a reader positioned after the seal
/// and the body slice without the CRC.
pub(crate) fn read_record(
    record: &[u8],
    magic: u32,
    seal_committed: u32,
    min_len: usize,
    max_len: usize,
) -> Result<Reader<'_>> {
    let mut reader = Reader::new(record);
    let got_magic = reader.u32()?;
    let format = reader.u16()?;
    let used_len = usize::from(reader.u16()?);
    let schema = reader.u32()?;
    let seal = reader.u32()?;
    if got_magic != magic
        || format != RECORD_FORMAT
        || used_len < min_len
        || used_len > max_len
        || used_len != record.len()
    {
        return err(Code::ProtocolError, "record head");
    }
    if seal != seal_committed {
        return err(Code::ProtocolError, "record uncommitted");
    }
    let crc = u32::from_be_bytes(record[used_len - 4..].try_into().expect("4"));
    if crc32_iso_hdlc(&record[..used_len - 4]) != crc {
        return err(Code::IntegrityError, "record crc");
    }
    if schema != RECORD_SCHEMA {
        return err(Code::Unsupported, "record schema");
    }
    Ok(Reader::new(&record[..used_len - 4]).skip(SEALED_HEAD_SIZE))
}

impl Reader<'_> {
    pub(crate) fn skip(mut self, count: usize) -> Self {
        self.pos = count.min(self.data.len());
        self
    }
}

// --- restricted ES256 COSE_Sign1 --------------------------------------------

/// Payload and signature of a restricted ES256 Sign1.
pub struct CoseParts<'a> {
    pub payload: &'a [u8],
    pub signature: [u8; 64],
}

/// `d2 84 43 a1 01 26 a0 <bstr payload> 58 40 <sig>`; minimal bstr heads,
/// payload length in [payload_min, payload_max], nothing trailing.
pub fn cose_es256_parse(
    object: &[u8],
    payload_min: usize,
    payload_max: usize,
    object_max: usize,
) -> Result<CoseParts<'_>> {
    if object.len() > object_max {
        return err(Code::ProtocolError, "cose object bounds");
    }
    if object.len() < SIGN1_HEAD.len() || object[..SIGN1_HEAD.len()] != SIGN1_HEAD {
        return err(Code::ProtocolError, "cose sign1 head");
    }
    let mut pos = SIGN1_HEAD.len();
    let payload = crate::cbor::read_bstr(object, &mut pos, "cose payload")?;
    let signature = crate::cbor::read_bstr(object, &mut pos, "cose signature")?;
    if payload.len() < payload_min
        || payload.len() > payload_max
        || signature.len() != 64
        || pos != object.len()
    {
        return err(Code::ProtocolError, "cose shape");
    }
    Ok(CoseParts {
        payload,
        signature: signature.try_into().expect("64"),
    })
}

/// `["Signature1", h'a10126', external_aad, payload]`.
pub fn cose_es256_sig_structure(payload: &[u8], external_aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + external_aad.len() + 24);
    out.push(0x84);
    out.push(0x6A);
    out.extend_from_slice(b"Signature1");
    crate::cbor::write_bstr(&mut out, &PROTECTED_ES256);
    crate::cbor::write_bstr(&mut out, external_aad);
    crate::cbor::write_bstr(&mut out, payload);
    out
}

pub fn cose_es256_assemble(payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 80);
    out.extend_from_slice(&SIGN1_HEAD);
    crate::cbor::write_bstr(&mut out, payload);
    crate::cbor::write_bstr(&mut out, signature);
    out
}

/// Low-S canonical ES256 verification over SHA-256(Sig_structure).
/// `false` for a non-canonical or failing signature or an invalid key.
pub fn cose_es256_verify(
    payload: &[u8],
    external_aad: &[u8],
    signature: &[u8; 64],
    pubkey: &[u8; 64],
) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if signature_range_check(signature).is_err() {
        return false;
    }
    let digest = sha256(&cose_es256_sig_structure(payload, external_aad));
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey);
    let Ok(key) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_prehash(&digest, &signature).is_ok()
}

/// Sign `Sig_structure` bytes through the custody seam (RFC 6979, low-S).
pub fn cose_es256_sign(
    signer: &dyn RootSigner,
    payload: &[u8],
    external_aad: &[u8],
) -> Result<[u8; 64]> {
    let signature = signer.sign(&cose_es256_sig_structure(payload, external_aad))?;
    signature_range_check(&signature).map_err(|_| {
        Error::new(
            Code::InternalError,
            "signer emitted a non-canonical signature",
        )
    })?;
    Ok(signature)
}
