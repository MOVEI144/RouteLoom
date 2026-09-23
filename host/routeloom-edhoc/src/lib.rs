//! EDHOC (RFC 9528) for the RouteLoom Site Authority — the host end of the
//! zero-touch join (docs/design/sdk-v1/02-zero-touch-join.md, plan P3-3).
//!
//! Scope, exactly what the join needs and what the RFC 9529 trace checks:
//!
//! - cipher suite 2 only (P-256 ECDH with x-only G_X/G_Y, ES256, SHA-256,
//!   AES-CCM-16-64-128, EDHOC MAC length 8);
//! - method 0 (signature both ways — RouteLoom's profile) and method 3
//!   (static DH both ways — the only suite-2 trace in RFC 9529, kept so the
//!   key schedule is checked byte for byte against the RFC);
//! - both roles; the Site Authority is the Responder, the Initiator exists
//!   for host tests and tooling;
//! - credentials referenced by `kid` only (`ID_CRED_x = {4: kid}`, compact
//!   in the plaintext), which is what the device backend (vendored libedhoc
//!   v2.3.2) can carry. The RLCW1 certificate itself travels by value in an
//!   EAD item that the caller's `resolve` callback reads (02 §3);
//! - EAD items (any label, optional bstr value), the error message
//!   (ERR_CODE 1 and 2) and EDHOC_Exporter.
//!
//! Not implemented: methods 1/2, suites other than 2, `kcwt`/`x5chain`
//! credentials by value in ID_CRED, EDHOC_KeyUpdate, message_4-less flows
//! (RouteLoom always sends message_4, 05 §3).
//!
//! Decoding is strict (deterministic CBOR only, canonical connection id /
//! kid encodings, no trailing bytes). One deliberate difference from
//! libedhoc: a one-byte C_x or kid sent as a bstr although it has an int
//! form (RFC 9529 §4.1.2) is refused here, while libedhoc accepts it as the
//! same value. Neither side emits that form, so the two interoperate.
//!
//! Every secret this crate holds (ephemeral scalar, PRKs) is wiped when the
//! session is dropped.

mod cbor;
pub mod crypto;

use std::fmt;

use zeroize::Zeroize;

use crypto::{
    aead_open, aead_seal, ecdh_x, ecdh_xy, edhoc_kdf, es256_sign, es256_verify, hkdf_extract,
    kdf32, public_key_x, sha256, AEAD_KEY_LEN, AEAD_NONCE_LEN, COORD_LEN, EDHOC_MAC_LEN, HASH_LEN,
    SIGNATURE_LEN,
};

/// The one cipher suite this crate runs.
pub const SUITE_2: i32 = 2;
/// Connection identifiers longer than this are refused: the device
/// backend is built with `CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID = 4`.
pub const CONN_ID_MAX: usize = 4;
/// Largest kid accepted (RouteLoom kids are SHA-256 of the COSE_Key).
pub const KID_MAX: usize = 32;
/// EAD items per message; libedhoc's `CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS`
/// on the device is 3, padding included.
pub const EAD_ITEMS_MAX: usize = 3;
/// SUITES_I entries accepted in message_1.
pub const SUITES_MAX: usize = 8;

/// ERR_CODE values (RFC 9528 §6.2).
pub const ERR_UNSPECIFIED: i64 = 1;
pub const ERR_WRONG_SELECTED_SUITE: i64 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The bytes are not a well-formed (deterministic) message.
    Decode(&'static str),
    /// Well formed but outside this implementation (method, credential form).
    Unsupported(&'static str),
    /// message_1 selected a suite other than 2: answer with an error
    /// message of ERR_CODE 2 ([`error_message_wrong_suite`]).
    WrongSelectedSuite,
    /// A primitive failed (bad scalar, point not on the curve, KDF length).
    Crypto(&'static str),
    /// MAC, signature or AEAD tag did not verify.
    Authentication(&'static str),
    /// The caller's credential resolver refused the peer.
    Credential(String),
    /// Method called out of order or after a failure.
    State(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(what) => write!(f, "edhoc decode: {what}"),
            Self::Unsupported(what) => write!(f, "edhoc unsupported: {what}"),
            Self::WrongSelectedSuite => write!(f, "edhoc: selected cipher suite not supported"),
            Self::Crypto(what) => write!(f, "edhoc crypto: {what}"),
            Self::Authentication(what) => write!(f, "edhoc authentication: {what}"),
            Self::Credential(what) => write!(f, "edhoc credential: {what}"),
            Self::State(what) => write!(f, "edhoc state: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    /// Method 0: both parties sign (RouteLoom's profile).
    SignatureSignature = 0,
    /// Method 3: both parties authenticate with static DH (RFC 9529 §3).
    StaticStatic = 3,
}

impl Method {
    fn from_i64(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::SignatureSignature),
            3 => Ok(Self::StaticStatic),
            1 | 2 => Err(Error::Unsupported("method 1/2")),
            _ => Err(Error::Decode("method")),
        }
    }

    fn mac_len(self) -> usize {
        match self {
            Self::SignatureSignature => HASH_LEN,
            Self::StaticStatic => EDHOC_MAC_LEN,
        }
    }
}

// --- EAD -----------------------------------------------------------------------

/// One EAD item (RFC 9528 §3.8): `ead_label: int, ? ead_value: bstr`. A
/// negative wire label marks the item critical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EadItem {
    /// The label as sent (negative = critical).
    pub label: i64,
    pub value: Option<Vec<u8>>,
}

impl EadItem {
    /// A critical item for the absolute label `label` (sent as `-label`).
    pub fn critical(label: u32, value: Vec<u8>) -> Self {
        Self {
            label: -i64::from(label),
            value: Some(value),
        }
    }

    pub fn is_critical(&self) -> bool {
        self.label < 0
    }

    /// |label| — what the item is, independent of criticality.
    pub fn absolute_label(&self) -> u64 {
        self.label.unsigned_abs()
    }

    pub fn is_padding(&self) -> bool {
        self.label == 0
    }
}

pub fn ead_encode(items: &[EadItem]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        cbor::write_int(&mut out, item.label);
        if let Some(value) = &item.value {
            cbor::write_bstr(&mut out, value);
        }
    }
    out
}

/// Parses an EAD field (possibly empty). At most [`EAD_ITEMS_MAX`] items.
pub fn ead_decode(bytes: &[u8]) -> Result<Vec<EadItem>> {
    let mut reader = cbor::Reader::new(bytes);
    let mut items = Vec::new();
    while !reader.at_end() {
        if !matches!(reader.peek_major(), Some(0 | 1)) {
            return Err(Error::Decode("ead label"));
        }
        let label = reader.int("ead label")?;
        let value = if reader.peek_major() == Some(2) {
            Some(reader.bstr("ead value")?.to_vec())
        } else {
            None
        };
        items.push(EadItem { label, value });
        if items.len() > EAD_ITEMS_MAX {
            return Err(Error::Unsupported("too many ead items"));
        }
    }
    Ok(items)
}

// --- identifiers -----------------------------------------------------------------

/// A one-byte identifier whose byte is itself the CBOR encoding of an
/// integer in -24..=23 is sent as that integer (RFC 9528 §3.3.2).
fn has_int_form(id: &[u8]) -> bool {
    id.len() == 1 && (id[0] <= 0x17 || (0x20..=0x37).contains(&id[0]))
}

fn write_identifier(out: &mut Vec<u8>, id: &[u8]) {
    if has_int_form(id) {
        out.push(id[0]);
    } else {
        cbor::write_bstr(out, id);
    }
}

fn read_identifier(
    reader: &mut cbor::Reader<'_>,
    max: usize,
    what: &'static str,
) -> Result<Vec<u8>> {
    match reader.peek_major() {
        Some(0 | 1) => {
            let start = reader.position();
            let value = reader.int(what)?;
            if !(-24..=23).contains(&value) || reader.position() != start + 1 {
                return Err(Error::Decode(what));
            }
            // The head byte itself is the one-byte identifier.
            let mut out = Vec::with_capacity(1);
            cbor::write_int(&mut out, value);
            Ok(out)
        }
        Some(2) => {
            let bytes = reader.bstr(what)?;
            if has_int_form(bytes) {
                return Err(Error::Decode(what)); // must have been sent as an int
            }
            if bytes.len() > max {
                return Err(Error::Unsupported(what));
            }
            Ok(bytes.to_vec())
        }
        Some(5) => Err(Error::Unsupported("ID_CRED map (only compact kid)")),
        _ => Err(Error::Decode(what)),
    }
}

/// `{4: kid}` — the full ID_CRED_x map used in MAC contexts and as the
/// COSE protected header.
fn id_cred_map(kid: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA1, 0x04];
    cbor::write_bstr(&mut out, kid);
    out
}

// --- credentials -------------------------------------------------------------------

/// Produces ES256 signatures over COSE `Sig_structure` bytes (SHA-256 is
/// applied inside). The Site Authority adapts its SAK custody seam here;
/// the private key never enters this crate.
pub trait Signer {
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; SIGNATURE_LEN]>;
}

/// A raw scalar as a [`Signer`] (tests and dev tools; RFC 6979).
pub struct ScalarSigner(pub [u8; 32]);

impl Signer for ScalarSigner {
    fn sign(&self, sig_structure: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        es256_sign(&self.0, sig_structure)
    }
}

impl Drop for ScalarSigner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub enum LocalKey<'a> {
    /// Method 0: authenticate by ES256 signature.
    Signature(&'a dyn Signer),
    /// Method 3: authenticate by static DH with this private scalar.
    StaticDh(&'a [u8; 32]),
}

/// The local party: `kid` (ID_CRED_x = {4: kid}), CRED_x as the CBOR data
/// item that is MACed and signed, and the authentication key.
pub struct LocalCredential<'a> {
    pub kid: &'a [u8],
    pub cred: &'a [u8],
    pub key: LocalKey<'a>,
}

/// What the resolver returns for an authenticated peer: CRED_x bytes and
/// the public authentication key (X || Y).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCredential {
    pub cred: Vec<u8>,
    pub public_key: [u8; 64],
}

// --- shared message pieces -------------------------------------------------------------

fn sig_structure(id_cred: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id_cred.len() + external_aad.len() + payload.len() + 24);
    out.push(0x84);
    cbor::write_tstr(&mut out, "Signature1");
    cbor::write_bstr(&mut out, id_cred);
    cbor::write_bstr(&mut out, external_aad);
    cbor::write_bstr(&mut out, payload);
    out
}

fn enc_structure(th: &[u8; HASH_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.push(0x83);
    cbor::write_tstr(&mut out, "Encrypt0");
    cbor::write_bstr(&mut out, &[]);
    cbor::write_bstr(&mut out, th);
    out
}

fn transcript(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part);
    }
    sha256(&data)
}

fn key_iv(
    prk: &[u8; HASH_LEN],
    key_label: u64,
    th: &[u8; HASH_LEN],
) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN])> {
    let key = edhoc_kdf(prk, key_label, th, AEAD_KEY_LEN)?;
    let iv = edhoc_kdf(prk, key_label + 1, th, AEAD_NONCE_LEN)?;
    let mut k = [0_u8; AEAD_KEY_LEN];
    let mut n = [0_u8; AEAD_NONCE_LEN];
    k.copy_from_slice(&key);
    n.copy_from_slice(&iv);
    Ok((k, n))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Signature_or_MAC for the local party: ES256 over the Sig_structure
/// (method 0) or the MAC itself (method 3).
fn authenticate(
    method: Method,
    local: &LocalCredential<'_>,
    id_cred: &[u8],
    external_aad: &[u8],
    mac: &[u8],
) -> Result<Vec<u8>> {
    match (method, &local.key) {
        (Method::SignatureSignature, LocalKey::Signature(signer)) => Ok(signer
            .sign(&sig_structure(id_cred, external_aad, mac))?
            .to_vec()),
        (Method::StaticStatic, LocalKey::StaticDh(_)) => Ok(mac.to_vec()),
        _ => Err(Error::State("local key does not match the method")),
    }
}

fn check_peer_authentication(
    method: Method,
    peer: &PeerCredential,
    id_cred: &[u8],
    external_aad: &[u8],
    mac: &[u8],
    received: &[u8],
    what: &'static str,
) -> Result<()> {
    let ok = match method {
        Method::SignatureSignature => {
            received.len() == SIGNATURE_LEN
                && es256_verify(
                    &peer.public_key,
                    &sig_structure(id_cred, external_aad, mac),
                    received,
                )
        }
        Method::StaticStatic => ct_eq(mac, received),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Authentication(what))
    }
}

fn check_local(local: &LocalCredential<'_>) -> Result<()> {
    if local.kid.is_empty() || local.kid.len() > KID_MAX {
        return Err(Error::State("local kid length"));
    }
    if local.cred.is_empty() {
        return Err(Error::State("local credential empty"));
    }
    Ok(())
}

fn check_connection_id(id: &[u8]) -> Result<()> {
    if id.len() > CONN_ID_MAX {
        return Err(Error::State("connection id too long"));
    }
    Ok(())
}

// --- error message -----------------------------------------------------------------------

/// ERR_CODE 1 (unspecified) with a diagnostic text. Keep it generic: the
/// peer is not authenticated.
pub fn error_message_unspecified(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_int(&mut out, ERR_UNSPECIFIED);
    cbor::write_tstr(&mut out, text);
    out
}

/// ERR_CODE 2 with SUITES_R (an int for one suite, else an array).
pub fn error_message_wrong_suite(suites_r: &[i32]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_int(&mut out, ERR_WRONG_SELECTED_SUITE);
    write_suites(&mut out, suites_r);
    out
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorInfo {
    Text(String),
    Suites(Vec<i32>),
    /// ERR_CODE without a readable ERR_INFO this crate interprets.
    Other,
}

/// Parses an EDHOC error message: `(ERR_CODE, ERR_INFO)`.
pub fn error_message_decode(bytes: &[u8]) -> Result<(i64, ErrorInfo)> {
    let mut reader = cbor::Reader::new(bytes);
    let code = reader.int("err_code")?;
    let info = match code {
        ERR_UNSPECIFIED => ErrorInfo::Text(reader.tstr("err_info")?.to_string()),
        ERR_WRONG_SELECTED_SUITE => ErrorInfo::Suites(read_suites(&mut reader)?),
        _ => {
            return Ok((code, ErrorInfo::Other));
        }
    };
    if !reader.at_end() {
        return Err(Error::Decode("error message trailing bytes"));
    }
    Ok((code, info))
}

fn write_suites(out: &mut Vec<u8>, suites: &[i32]) {
    if suites.len() == 1 {
        cbor::write_int(out, i64::from(suites[0]));
    } else {
        cbor::write_head(out, 4, suites.len() as u64);
        for &suite in suites {
            cbor::write_int(out, i64::from(suite));
        }
    }
}

fn read_suites(reader: &mut cbor::Reader<'_>) -> Result<Vec<i32>> {
    let suite = |reader: &mut cbor::Reader<'_>| -> Result<i32> {
        let value = reader.int("suite")?;
        i32::try_from(value).map_err(|_| Error::Decode("suite"))
    };
    match reader.peek_major() {
        Some(0 | 1) => Ok(vec![suite(reader)?]),
        Some(4) => {
            let count = reader.array("suites")?;
            // One suite must be sent as an int, not a one-element array
            // (RFC 9528 §5.2.2; RFC 9529 §4.1.3).
            if count < 2 || count as usize > SUITES_MAX {
                return Err(Error::Decode("suites array length"));
            }
            (0..count).map(|_| suite(reader)).collect()
        }
        _ => Err(Error::Decode("suites")),
    }
}

// --- Responder -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Start,
    Message1,
    Message2,
    Message3,
    Message4,
    Failed,
}

/// Secrets of one exchange; wiped on drop.
#[derive(Default)]
struct Secrets {
    ephemeral: [u8; 32],
    prk_2e: [u8; HASH_LEN],
    prk_3e2m: [u8; HASH_LEN],
    prk_4e3m: [u8; HASH_LEN],
    prk_out: [u8; HASH_LEN],
    prk_exporter: [u8; HASH_LEN],
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.ephemeral.zeroize();
        self.prk_2e.zeroize();
        self.prk_3e2m.zeroize();
        self.prk_4e3m.zeroize();
        self.prk_out.zeroize();
        self.prk_exporter.zeroize();
    }
}

/// What message_1 said.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message1 {
    pub method: Method,
    pub suites_i: Vec<i32>,
    pub c_i: Vec<u8>,
    pub ead: Vec<EadItem>,
}

/// What message_3 said, once authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message3 {
    pub kid: Vec<u8>,
    pub ead: Vec<EadItem>,
    pub peer: PeerCredential,
}

/// What message_2 said, once authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message2 {
    pub c_r: Vec<u8>,
    pub kid: Vec<u8>,
    pub ead: Vec<EadItem>,
    pub peer: PeerCredential,
}

/// Decodes message_1 (RFC 9528 §5.2.1) for `method`.
fn parse_message_1(message: &[u8], method: Method) -> Result<(Message1, [u8; COORD_LEN])> {
    let mut reader = cbor::Reader::new(message);
    if !matches!(reader.peek_major(), Some(0 | 1)) {
        return Err(Error::Decode("method"));
    }
    let received = Method::from_i64(reader.int("method")?)?;
    if received != method {
        return Err(Error::Unsupported("method not offered by this responder"));
    }
    let suites_i = read_suites(&mut reader)?;
    let g_x = reader.bstr("G_X")?;
    if g_x.len() != COORD_LEN {
        return Err(Error::Decode("G_X length"));
    }
    let c_i = read_identifier(&mut reader, CONN_ID_MAX, "C_I")?;
    let ead = ead_decode(reader.rest())?;
    if suites_i.last() != Some(&SUITE_2) {
        return Err(Error::WrongSelectedSuite);
    }
    crypto::check_x(g_x)?;
    let mut x = [0_u8; COORD_LEN];
    x.copy_from_slice(g_x);
    Ok((
        Message1 {
            method: received,
            suites_i,
            c_i,
            ead,
        },
        x,
    ))
}

/// The Responder — the Site Authority's side of the join exchange.
pub struct Responder {
    method: Method,
    c_r: Vec<u8>,
    step: Step,
    c_i: Vec<u8>,
    g_x: [u8; COORD_LEN],
    h_message_1: [u8; HASH_LEN],
    th_3: [u8; HASH_LEN],
    th_4: [u8; HASH_LEN],
    secrets: Secrets,
}

impl Responder {
    /// `c_r`: this side's connection identifier (0..=CONN_ID_MAX bytes).
    pub fn new(method: Method, c_r: Vec<u8>) -> Result<Self> {
        check_connection_id(&c_r)?;
        Ok(Self {
            method,
            c_r,
            step: Step::Start,
            c_i: Vec::new(),
            g_x: [0; COORD_LEN],
            h_message_1: [0; HASH_LEN],
            th_3: [0; HASH_LEN],
            th_4: [0; HASH_LEN],
            secrets: Secrets::default(),
        })
    }

    fn expect(&mut self, step: Step) -> Result<()> {
        if self.step != step {
            self.step = Step::Failed;
            return Err(Error::State("message out of order"));
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: Error) -> Result<T> {
        self.step = Step::Failed;
        Err(error)
    }

    pub fn c_r(&self) -> &[u8] {
        &self.c_r
    }

    pub fn c_i(&self) -> &[u8] {
        &self.c_i
    }

    /// message_1 → its fields. [`Error::WrongSelectedSuite`] asks the
    /// caller to answer [`error_message_wrong_suite`]`(&[SUITE_2])`.
    pub fn process_message_1(&mut self, message: &[u8]) -> Result<Message1> {
        self.expect(Step::Start)?;
        match parse_message_1(message, self.method) {
            Ok((parsed, g_x)) => {
                self.g_x = g_x;
                self.c_i = parsed.c_i.clone();
                self.h_message_1 = sha256(message);
                self.step = Step::Message1;
                Ok(parsed)
            }
            Err(error) => self.fail(error),
        }
    }

    /// message_2 with the ephemeral scalar `y` (fresh per exchange:
    /// [`crypto::random_scalar`]; tests replay the RFC's).
    pub fn compose_message_2(
        &mut self,
        y: [u8; 32],
        local: &LocalCredential<'_>,
        ead_2: &[EadItem],
    ) -> Result<Vec<u8>> {
        self.expect(Step::Message1)?;
        match self.compose_message_2_inner(y, local, ead_2) {
            Ok(message) => {
                self.step = Step::Message2;
                Ok(message)
            }
            Err(error) => self.fail(error),
        }
    }

    fn compose_message_2_inner(
        &mut self,
        y: [u8; 32],
        local: &LocalCredential<'_>,
        ead_2: &[EadItem],
    ) -> Result<Vec<u8>> {
        check_local(local)?;
        self.secrets.ephemeral = y;
        let g_y = public_key_x(&y)?;
        let g_xy = ecdh_x(&y, &self.g_x)?;
        let th_2 = transcript(&[&cbor::bstr(&g_y), &cbor::bstr(&self.h_message_1)]);
        self.secrets.prk_2e = hkdf_extract(&th_2, &g_xy);
        self.secrets.prk_3e2m = match (self.method, &local.key) {
            (Method::SignatureSignature, LocalKey::Signature(_)) => self.secrets.prk_2e,
            (Method::StaticStatic, LocalKey::StaticDh(r)) => {
                let salt = kdf32(&self.secrets.prk_2e, 1, &th_2)?;
                hkdf_extract(&salt, &ecdh_x(r, &self.g_x)?)
            }
            _ => return Err(Error::State("local key does not match the method")),
        };
        let id_cred = id_cred_map(local.kid);
        let ead = ead_encode(ead_2);
        let mut c_r = Vec::new();
        write_identifier(&mut c_r, &self.c_r);
        let th_2_bstr = cbor::bstr(&th_2);
        let context_2 = [&c_r[..], &id_cred, &th_2_bstr, local.cred, &ead].concat();
        let mac_2 = edhoc_kdf(&self.secrets.prk_3e2m, 2, &context_2, self.method.mac_len())?;
        let external_aad = [&th_2_bstr[..], local.cred, &ead].concat();
        let signature_or_mac = authenticate(self.method, local, &id_cred, &external_aad, &mac_2)?;
        let mut plaintext = c_r;
        write_identifier(&mut plaintext, local.kid);
        cbor::write_bstr(&mut plaintext, &signature_or_mac);
        plaintext.extend_from_slice(&ead);
        let keystream = edhoc_kdf(&self.secrets.prk_2e, 0, &th_2, plaintext.len())?;
        let mut body = g_y.to_vec();
        body.extend(plaintext.iter().zip(&keystream).map(|(p, k)| p ^ k));
        self.th_3 = transcript(&[&th_2_bstr, &plaintext, local.cred]);
        Ok(cbor::bstr(&body))
    }

    /// message_3 → the Initiator's kid and EAD_3, authenticated. `resolve`
    /// gets the kid and the EAD_3 items (a certificate carried by value is
    /// there) and must return the validated credential, or refuse.
    pub fn process_message_3<F>(&mut self, message: &[u8], resolve: F) -> Result<Message3>
    where
        F: FnOnce(&[u8], &[EadItem]) -> core::result::Result<PeerCredential, String>,
    {
        self.expect(Step::Message2)?;
        match self.process_message_3_inner(message, resolve) {
            Ok(parsed) => {
                self.step = Step::Message3;
                Ok(parsed)
            }
            Err(error) => self.fail(error),
        }
    }

    fn process_message_3_inner<F>(&mut self, message: &[u8], resolve: F) -> Result<Message3>
    where
        F: FnOnce(&[u8], &[EadItem]) -> core::result::Result<PeerCredential, String>,
    {
        let mut reader = cbor::Reader::new(message);
        let sealed = reader.bstr("message_3")?;
        if !reader.at_end() {
            return Err(Error::Decode("message_3 trailing bytes"));
        }
        let (k_3, iv_3) = key_iv(&self.secrets.prk_3e2m, 3, &self.th_3)?;
        let plaintext = aead_open(&k_3, &iv_3, &enc_structure(&self.th_3), sealed)?;
        let mut pt = cbor::Reader::new(&plaintext);
        let kid = read_identifier(&mut pt, KID_MAX, "ID_CRED_I")?;
        let received = pt.bstr("Signature_or_MAC_3")?.to_vec();
        let ead_bytes = pt.rest().to_vec();
        let ead = ead_decode(&ead_bytes)?;
        let peer = resolve(&kid, &ead).map_err(Error::Credential)?;
        self.secrets.prk_4e3m = match self.method {
            Method::SignatureSignature => self.secrets.prk_3e2m,
            Method::StaticStatic => {
                let salt = kdf32(&self.secrets.prk_3e2m, 5, &self.th_3)?;
                hkdf_extract(&salt, &ecdh_xy(&self.secrets.ephemeral, &peer.public_key)?)
            }
        };
        let id_cred = id_cred_map(&kid);
        let th_3_bstr = cbor::bstr(&self.th_3);
        let context_3 = [&id_cred[..], &th_3_bstr, &peer.cred, &ead_bytes].concat();
        let mac_3 = edhoc_kdf(&self.secrets.prk_4e3m, 6, &context_3, self.method.mac_len())?;
        let external_aad = [&th_3_bstr[..], &peer.cred, &ead_bytes].concat();
        check_peer_authentication(
            self.method,
            &peer,
            &id_cred,
            &external_aad,
            &mac_3,
            &received,
            "Signature_or_MAC_3",
        )?;
        self.th_4 = transcript(&[&th_3_bstr, &plaintext, &peer.cred]);
        self.secrets.prk_out = kdf32(&self.secrets.prk_4e3m, 7, &self.th_4)?;
        self.secrets.prk_exporter = kdf32(&self.secrets.prk_out, 10, &[])?;
        Ok(Message3 { kid, ead, peer })
    }

    /// message_4 carrying EAD_4 (possibly none).
    pub fn compose_message_4(&mut self, ead_4: &[EadItem]) -> Result<Vec<u8>> {
        self.expect(Step::Message3)?;
        match compose_message_4(&self.secrets.prk_4e3m, &self.th_4, ead_4) {
            Ok(message) => {
                self.step = Step::Message4;
                Ok(message)
            }
            Err(error) => self.fail(error),
        }
    }

    /// EDHOC_Exporter(label, context, length) (§4.2.1), after message_3.
    pub fn exporter(&self, label: u64, context: &[u8], length: usize) -> Result<Vec<u8>> {
        if !matches!(self.step, Step::Message3 | Step::Message4) {
            return Err(Error::State("exporter before the exchange completed"));
        }
        edhoc_kdf(&self.secrets.prk_exporter, label, context, length)
    }

    /// PRK_out (§4.1.3), after message_3 — test and diagnostic access.
    pub fn prk_out(&self) -> Option<[u8; HASH_LEN]> {
        matches!(self.step, Step::Message3 | Step::Message4).then_some(self.secrets.prk_out)
    }
}

fn compose_message_4(
    prk_4e3m: &[u8; HASH_LEN],
    th_4: &[u8; HASH_LEN],
    ead_4: &[EadItem],
) -> Result<Vec<u8>> {
    let (k_4, iv_4) = key_iv(prk_4e3m, 8, th_4)?;
    let sealed = aead_seal(&k_4, &iv_4, &enc_structure(th_4), &ead_encode(ead_4))?;
    Ok(cbor::bstr(&sealed))
}

// --- Initiator -------------------------------------------------------------------------

/// The Initiator (the joining device's role) — for host tests, interop
/// checks and tooling; the device itself runs libedhoc.
pub struct Initiator {
    method: Method,
    suites_i: Vec<i32>,
    c_i: Vec<u8>,
    step: Step,
    message_1: Vec<u8>,
    g_y: [u8; COORD_LEN],
    th_3: [u8; HASH_LEN],
    th_4: [u8; HASH_LEN],
    secrets: Secrets,
}

impl Initiator {
    /// `suites_i` in preference order with the selected suite (2) last.
    pub fn new(method: Method, suites_i: Vec<i32>, c_i: Vec<u8>) -> Result<Self> {
        check_connection_id(&c_i)?;
        if suites_i.is_empty() || suites_i.len() > SUITES_MAX {
            return Err(Error::State("suites_i length"));
        }
        Ok(Self {
            method,
            suites_i,
            c_i,
            step: Step::Start,
            message_1: Vec::new(),
            g_y: [0; COORD_LEN],
            th_3: [0; HASH_LEN],
            th_4: [0; HASH_LEN],
            secrets: Secrets::default(),
        })
    }

    fn expect(&mut self, step: Step) -> Result<()> {
        if self.step != step {
            self.step = Step::Failed;
            return Err(Error::State("message out of order"));
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: Error) -> Result<T> {
        self.step = Step::Failed;
        Err(error)
    }

    pub fn compose_message_1(&mut self, x: [u8; 32], ead_1: &[EadItem]) -> Result<Vec<u8>> {
        self.expect(Step::Start)?;
        let g_x = match public_key_x(&x) {
            Ok(g_x) => g_x,
            Err(error) => return self.fail(error),
        };
        self.secrets.ephemeral = x;
        let mut out = Vec::new();
        cbor::write_int(&mut out, self.method as i64);
        write_suites(&mut out, &self.suites_i);
        cbor::write_bstr(&mut out, &g_x);
        write_identifier(&mut out, &self.c_i);
        out.extend_from_slice(&ead_encode(ead_1));
        self.message_1 = out.clone();
        self.step = Step::Message1;
        Ok(out)
    }

    /// message_2 → the Responder's C_R, kid and EAD_2, authenticated.
    pub fn process_message_2<F>(&mut self, message: &[u8], resolve: F) -> Result<Message2>
    where
        F: FnOnce(&[u8], &[EadItem]) -> core::result::Result<PeerCredential, String>,
    {
        self.expect(Step::Message1)?;
        match self.process_message_2_inner(message, resolve) {
            Ok(parsed) => {
                self.step = Step::Message2;
                Ok(parsed)
            }
            Err(error) => self.fail(error),
        }
    }

    fn process_message_2_inner<F>(&mut self, message: &[u8], resolve: F) -> Result<Message2>
    where
        F: FnOnce(&[u8], &[EadItem]) -> core::result::Result<PeerCredential, String>,
    {
        let mut reader = cbor::Reader::new(message);
        let body = reader.bstr("message_2")?;
        if !reader.at_end() {
            return Err(Error::Decode("message_2 trailing bytes"));
        }
        if body.len() <= COORD_LEN {
            return Err(Error::Decode("message_2 length"));
        }
        let (g_y, ciphertext) = body.split_at(COORD_LEN);
        let g_xy = ecdh_x(&self.secrets.ephemeral, g_y)?;
        self.g_y.copy_from_slice(g_y);
        let th_2 = transcript(&[&cbor::bstr(g_y), &cbor::bstr(&sha256(&self.message_1))]);
        self.secrets.prk_2e = hkdf_extract(&th_2, &g_xy);
        let keystream = edhoc_kdf(&self.secrets.prk_2e, 0, &th_2, ciphertext.len())?;
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(&keystream)
            .map(|(c, k)| c ^ k)
            .collect();
        let mut pt = cbor::Reader::new(&plaintext);
        let c_r_start = pt.position();
        let c_r = read_identifier(&mut pt, CONN_ID_MAX, "C_R")?;
        let c_r_encoded = plaintext[c_r_start..pt.position()].to_vec();
        let kid = read_identifier(&mut pt, KID_MAX, "ID_CRED_R")?;
        let received = pt.bstr("Signature_or_MAC_2")?.to_vec();
        let ead_bytes = pt.rest().to_vec();
        let ead = ead_decode(&ead_bytes)?;
        let peer = resolve(&kid, &ead).map_err(Error::Credential)?;
        self.secrets.prk_3e2m = match self.method {
            Method::SignatureSignature => self.secrets.prk_2e,
            Method::StaticStatic => {
                let salt = kdf32(&self.secrets.prk_2e, 1, &th_2)?;
                hkdf_extract(&salt, &ecdh_xy(&self.secrets.ephemeral, &peer.public_key)?)
            }
        };
        let id_cred = id_cred_map(&kid);
        let th_2_bstr = cbor::bstr(&th_2);
        let context_2 = [
            &c_r_encoded[..],
            &id_cred,
            &th_2_bstr,
            &peer.cred,
            &ead_bytes,
        ]
        .concat();
        let mac_2 = edhoc_kdf(&self.secrets.prk_3e2m, 2, &context_2, self.method.mac_len())?;
        let external_aad = [&th_2_bstr[..], &peer.cred, &ead_bytes].concat();
        check_peer_authentication(
            self.method,
            &peer,
            &id_cred,
            &external_aad,
            &mac_2,
            &received,
            "Signature_or_MAC_2",
        )?;
        self.th_3 = transcript(&[&th_2_bstr, &plaintext, &peer.cred]);
        Ok(Message2 {
            c_r,
            kid,
            ead,
            peer,
        })
    }

    pub fn compose_message_3(
        &mut self,
        local: &LocalCredential<'_>,
        ead_3: &[EadItem],
    ) -> Result<Vec<u8>> {
        self.expect(Step::Message2)?;
        match self.compose_message_3_inner(local, ead_3) {
            Ok(message) => {
                self.step = Step::Message3;
                Ok(message)
            }
            Err(error) => self.fail(error),
        }
    }

    fn compose_message_3_inner(
        &mut self,
        local: &LocalCredential<'_>,
        ead_3: &[EadItem],
    ) -> Result<Vec<u8>> {
        check_local(local)?;
        self.secrets.prk_4e3m = match (self.method, &local.key) {
            (Method::SignatureSignature, LocalKey::Signature(_)) => self.secrets.prk_3e2m,
            (Method::StaticStatic, LocalKey::StaticDh(i)) => {
                let salt = kdf32(&self.secrets.prk_3e2m, 5, &self.th_3)?;
                // G_IY: the Initiator's static scalar with the Responder's G_Y.
                hkdf_extract(&salt, &ecdh_x(i, &self.g_y)?)
            }
            _ => return Err(Error::State("local key does not match the method")),
        };
        let id_cred = id_cred_map(local.kid);
        let ead = ead_encode(ead_3);
        let th_3_bstr = cbor::bstr(&self.th_3);
        let context_3 = [&id_cred[..], &th_3_bstr, local.cred, &ead].concat();
        let mac_3 = edhoc_kdf(&self.secrets.prk_4e3m, 6, &context_3, self.method.mac_len())?;
        let external_aad = [&th_3_bstr[..], local.cred, &ead].concat();
        let signature_or_mac = authenticate(self.method, local, &id_cred, &external_aad, &mac_3)?;
        let mut plaintext = Vec::new();
        write_identifier(&mut plaintext, local.kid);
        cbor::write_bstr(&mut plaintext, &signature_or_mac);
        plaintext.extend_from_slice(&ead);
        let (k_3, iv_3) = key_iv(&self.secrets.prk_3e2m, 3, &self.th_3)?;
        let sealed = aead_seal(&k_3, &iv_3, &enc_structure(&self.th_3), &plaintext)?;
        self.th_4 = transcript(&[&th_3_bstr, &plaintext, local.cred]);
        self.secrets.prk_out = kdf32(&self.secrets.prk_4e3m, 7, &self.th_4)?;
        self.secrets.prk_exporter = kdf32(&self.secrets.prk_out, 10, &[])?;
        Ok(cbor::bstr(&sealed))
    }

    /// message_4 → EAD_4 (possibly empty), after the tag verified.
    pub fn process_message_4(&mut self, message: &[u8]) -> Result<Vec<EadItem>> {
        self.expect(Step::Message3)?;
        let result = (|| {
            let mut reader = cbor::Reader::new(message);
            let sealed = reader.bstr("message_4")?;
            if !reader.at_end() {
                return Err(Error::Decode("message_4 trailing bytes"));
            }
            let (k_4, iv_4) = key_iv(&self.secrets.prk_4e3m, 8, &self.th_4)?;
            let plaintext = aead_open(&k_4, &iv_4, &enc_structure(&self.th_4), sealed)?;
            ead_decode(&plaintext)
        })();
        match result {
            Ok(ead) => {
                self.step = Step::Message4;
                Ok(ead)
            }
            Err(error) => self.fail(error),
        }
    }

    pub fn exporter(&self, label: u64, context: &[u8], length: usize) -> Result<Vec<u8>> {
        if !matches!(self.step, Step::Message3 | Step::Message4) {
            return Err(Error::State("exporter before the exchange completed"));
        }
        edhoc_kdf(&self.secrets.prk_exporter, label, context, length)
    }

    pub fn prk_out(&self) -> Option<[u8; HASH_LEN]> {
        matches!(self.step, Step::Message3 | Step::Message4).then_some(self.secrets.prk_out)
    }
}
