//! RouteLoom mesh wire codec — the frozen "Wire v1" byte layout for the
//! CORE_FIXED_250 profile, mirrored field-for-field from the C++ implementation
//! in `components/routeloom/src/wire.cpp`. All fields are fixed-width
//! big-endian. The crypto suite is still pending (G-SEC); the shared golden
//! vectors in `protocol/golden/` use the deterministic test cipher in
//! [`test_security`] so C++ and Rust produce identical bytes.
//!
//! Header layout (`HEADER_SIZE` = 88 bytes); "E" marks end-immutable fields
//! (covered by the end-to-end AAD) and "H" hop-mutable fields (rewritten by
//! relays, covered only by the link AAD over the complete header):
//!
//! ```text
//! offset  size  field
//! 0       2     magic 0x524C "RL"                 E
//! 2       1     major version (= 1)               E
//! 3       1     minor version (= 0)               E
//! 4       1     frame type                        E
//! 5       1     flags                             E
//! 6       1     delivery class                    E
//! 7       1     delivery round                    H
//! 8       1     hop remaining                     H
//! 9       1     reserved, must be 0               -
//! 10      2     payload length                    E
//! 12      4     network id (low 32 bits)          E
//! 16      8     origin node id                    E
//! 24      8     destination node id               E
//! 32      8     previous hop                      H
//! 40      8     next hop                          H
//! 48      4     message session (boot session)    E
//! 52      8     message sequence                  E
//! 60      4     remaining deadline ms             H
//! 64      4     original lifetime ms              E
//! 68      2     link epoch                        H
//! 70      2     end epoch                         E
//! 72      8     link crypto counter               H
//! 80      8     end crypto counter                E
//! 88      n     link ciphertext: payload [+ end tag if FLAG_END_PROTECTED]
//! 88+n    16    link AEAD tag (AAD = complete 88-byte header)
//! ```
//!
//! Message ID = origin + session + sequence; delivery round, crypto counters
//! and the boot session are distinct fields and must not be conflated.

use std::fmt;

pub mod admission;
pub mod autonomy;
pub mod endpoint;
pub mod group;
pub mod test_security;

pub const MAGIC: u16 = 0x524c;
pub const MAJOR: u8 = 2;
pub const MINOR: u8 = 0;
pub const HEADER_SIZE: usize = 88;
/// `END_PROTECTED` flag; every other flag bit is reserved and must be zero.
pub const FLAG_END_PROTECTED: u8 = 0x01;
pub const MAX_APPLICATION_PAYLOAD: usize = 128;
pub const MAX_ESPNOW_BODY: usize = 250;
pub const AEAD_TAG_SIZE: usize = 16;
/// Largest crypto counter: Wire v2 carries u48 counters. A context that
/// reaches it must move to a new epoch — counters never wrap under one key.
pub const MAX_CRYPTO_COUNTER: u64 = 0xFFFF_FFFF_FFFF;
pub const DEFAULT_HOP_LIMIT: u8 = 10;
pub const INVALID_NODE_ID: u64 = 0;
pub const BROADCAST_NODE_ID: u64 = u64::MAX;

const _: () = assert!(
    HEADER_SIZE + MAX_APPLICATION_PAYLOAD + 2 * AEAD_TAG_SIZE <= MAX_ESPNOW_BODY,
    "wire v1 envelope must fit the 250-byte ESP-NOW body"
);

/// Frozen Wire v1 frame type IDs (protocol/semantics.json `frame_numeric_ids`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    Discover = 1,
    Offer = 2,
    BootstrapAuth = 3,
    MembershipResult = 4,
    BootstrapChunk = 5,
    BootstrapReply = 6,
    MembershipQuery = 7,
    Data = 16,
    HopAccept = 17,
    EndReceipt = 18,
    AppResult = 19,
    Busy = 20,
    Service = 21,
    Control = 22,
    TimeSync = 23,
    ChannelNotice = 24,
    /// Group delivery (docs/design/sdk-v1/group-delivery.md): end-protected
    /// under [`SecurityScope::Group`], forwarded along the gateway tree.
    GroupData = 25,
    /// Link-only aggregated confirmation, child -> tree parent.
    GroupReport = 26,
    RouteUpdate = 32,
    RouteWithdraw = 33,
    SeqnoRequest = 34,
    RouteRequest = 35,
    NeighborProbe = 40,
    NeighborResult = 41,
    Diagnostic = 48,
    ControlObject = 49,
    ObjectChunk = 50,
    ObjectAck = 51,
}

impl TryFrom<u8> for FrameType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::BootstrapAuth,
            4 => Self::MembershipResult,
            5 => Self::BootstrapChunk,
            6 => Self::BootstrapReply,
            7 => Self::MembershipQuery,
            16 => Self::Data,
            17 => Self::HopAccept,
            18 => Self::EndReceipt,
            19 => Self::AppResult,
            20 => Self::Busy,
            21 => Self::Service,
            22 => Self::Control,
            23 => Self::TimeSync,
            24 => Self::ChannelNotice,
            25 => Self::GroupData,
            26 => Self::GroupReport,
            32 => Self::RouteUpdate,
            33 => Self::RouteWithdraw,
            34 => Self::SeqnoRequest,
            35 => Self::RouteRequest,
            40 => Self::NeighborProbe,
            41 => Self::NeighborResult,
            48 => Self::Diagnostic,
            49 => Self::ControlObject,
            50 => Self::ObjectChunk,
            51 => Self::ObjectAck,
            _ => {
                return Err(WireError::new(
                    ErrorCode::ProtocolError,
                    "unknown frame type",
                ))
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum DeliveryClass {
    BestEffort = 0,
    #[default]
    Reliable = 1,
    Applied = 2,
}

impl TryFrom<u8> for DeliveryClass {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::BestEffort,
            1 => Self::Reliable,
            2 => Self::Applied,
            _ => {
                return Err(WireError::new(
                    ErrorCode::ProtocolError,
                    "unknown delivery class",
                ))
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecurityScope {
    Link = 0,
    EndToEnd = 1,
    /// GROUP_DATA end protection: sender = origin, receiver = group address.
    Group = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityContext {
    pub scope: SecurityScope,
    pub network: u64,
    pub sender: u64,
    pub receiver: u64,
    /// Wire v2: 32-bit, never wraps in a device lifetime.
    pub epoch: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MessageId {
    pub session: u32,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidArgument,
    InvalidState,
    Unsupported,
    NoCapacity,
    Expired,
    AuthenticationFailed,
    AuthorizationFailed,
    ProtocolError,
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireError {
    pub code: ErrorCode,
    pub detail: &'static str,
}

impl WireError {
    pub const fn new(code: ErrorCode, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for WireError {}

pub type Result<T> = std::result::Result<T, WireError>;

/// Mirror of the C++ `SecurityProvider` interface.
pub trait SecurityProvider {
    fn ready(&self) -> bool;
    fn next_counter(&mut self, context: &SecurityContext) -> Result<u64>;
    fn seal(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_SIZE]>;
    fn open(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AEAD_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct Header {
    pub frame_type: FrameType,
    pub flags: u8,
    pub delivery: DeliveryClass,
    pub delivery_round: u8,
    pub hop_remaining: u8,
    pub payload_length: u16,
    /// v1 encodes the low 32 bits; upper bits must be zero.
    pub network: u64,
    pub origin: u64,
    pub destination: u64,
    pub previous_hop: u64,
    pub next_hop: u64,
    pub message: MessageId,
    pub remaining_deadline_ms: u32,
    pub original_lifetime_ms: u32,
    pub link_epoch: u32,
    pub end_epoch: u32,
    /// `<= MAX_CRYPTO_COUNTER` (u48 on the wire).
    pub link_counter: u64,
    /// `<= MAX_CRYPTO_COUNTER` (u48 on the wire).
    pub end_counter: u64,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            frame_type: FrameType::Data,
            flags: 0,
            delivery: DeliveryClass::Reliable,
            delivery_round: 0,
            hop_remaining: DEFAULT_HOP_LIMIT,
            payload_length: 0,
            network: 0,
            origin: INVALID_NODE_ID,
            destination: INVALID_NODE_ID,
            previous_hop: INVALID_NODE_ID,
            next_hop: INVALID_NODE_ID,
            message: MessageId::default(),
            remaining_deadline_ms: 0,
            original_lifetime_ms: 0,
            link_epoch: 0,
            end_epoch: 0,
            link_counter: 0,
            end_counter: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlainFrame {
    pub header: Header,
    pub payload: [u8; MAX_APPLICATION_PAYLOAD],
    pub payload_size: usize,
}

impl Default for PlainFrame {
    fn default() -> Self {
        Self {
            header: Header::default(),
            payload: [0; MAX_APPLICATION_PAYLOAD],
            payload_size: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LinkOpenedFrame {
    pub header: Header,
    pub protected_payload: [u8; MAX_APPLICATION_PAYLOAD + AEAD_TAG_SIZE],
    pub protected_payload_size: usize,
}

impl Default for LinkOpenedFrame {
    fn default() -> Self {
        Self {
            header: Header::default(),
            protected_payload: [0; MAX_APPLICATION_PAYLOAD + AEAD_TAG_SIZE],
            protected_payload_size: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedFrame {
    pub bytes: [u8; MAX_ESPNOW_BODY],
    pub size: usize,
}

impl Default for EncodedFrame {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_ESPNOW_BODY],
            size: 0,
        }
    }
}

impl EncodedFrame {
    pub fn view(&self) -> &[u8] {
        &self.bytes[..self.size]
    }
}

const fn err<T>(code: ErrorCode, detail: &'static str) -> Result<T> {
    Err(WireError::new(code, detail))
}

/// 48-bit big-endian encoding of a crypto counter.
fn u48_be(value: u64) -> Result<[u8; 6]> {
    if value > MAX_CRYPTO_COUNTER {
        return err(ErrorCode::InvalidArgument, "crypto counter exceeds 48 bits");
    }
    let bytes = value.to_be_bytes();
    Ok(bytes[2..8].try_into().expect("six bytes"))
}

fn read_u48(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

fn write_header(header: &Header, output: &mut [u8; HEADER_SIZE]) -> Result<()> {
    if header.network > u64::from(u32::MAX) {
        return err(ErrorCode::InvalidArgument, "v1 network id exceeds 32 bits");
    }
    output[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    output[2] = MAJOR;
    output[3] = MINOR;
    output[4] = header.frame_type as u8;
    output[5] = header.flags;
    output[6] = header.delivery as u8;
    output[7] = header.delivery_round;
    output[8] = header.hop_remaining;
    output[9] = 0;
    output[10..12].copy_from_slice(&header.payload_length.to_be_bytes());
    output[12..16].copy_from_slice(&(header.network as u32).to_be_bytes());
    output[16..24].copy_from_slice(&header.origin.to_be_bytes());
    output[24..32].copy_from_slice(&header.destination.to_be_bytes());
    output[32..40].copy_from_slice(&header.previous_hop.to_be_bytes());
    output[40..48].copy_from_slice(&header.next_hop.to_be_bytes());
    output[48..52].copy_from_slice(&header.message.session.to_be_bytes());
    output[52..60].copy_from_slice(&header.message.sequence.to_be_bytes());
    output[60..64].copy_from_slice(&header.remaining_deadline_ms.to_be_bytes());
    output[64..68].copy_from_slice(&header.original_lifetime_ms.to_be_bytes());
    output[68..72].copy_from_slice(&header.link_epoch.to_be_bytes());
    output[72..76].copy_from_slice(&header.end_epoch.to_be_bytes());
    output[76..82].copy_from_slice(&u48_be(header.link_counter)?);
    output[82..88].copy_from_slice(&u48_be(header.end_counter)?);
    Ok(())
}

fn read_header(encoded: &[u8], header: &mut Header) -> Result<()> {
    if encoded.len() < HEADER_SIZE + AEAD_TAG_SIZE {
        return err(ErrorCode::ProtocolError, "wire frame too short");
    }
    let fixed: &[u8; HEADER_SIZE] = encoded[..HEADER_SIZE].try_into().expect("fixed length");
    let magic = u16::from_be_bytes(fixed[0..2].try_into().expect("fixed length"));
    let major = fixed[2];
    let minor = fixed[3];
    let frame_type = FrameType::try_from(fixed[4])?;
    let flags = fixed[5];
    let delivery = DeliveryClass::try_from(fixed[6])?;
    let reserved = fixed[9];
    if magic != MAGIC || major != MAJOR || minor > MINOR || reserved != 0 {
        return err(ErrorCode::ProtocolError, "unsupported wire header");
    }
    header.frame_type = frame_type;
    header.flags = flags;
    header.delivery = delivery;
    header.delivery_round = fixed[7];
    header.hop_remaining = fixed[8];
    header.payload_length = u16::from_be_bytes(fixed[10..12].try_into().expect("fixed length"));
    header.network = u64::from(u32::from_be_bytes(
        fixed[12..16].try_into().expect("fixed length"),
    ));
    header.origin = u64::from_be_bytes(fixed[16..24].try_into().expect("fixed length"));
    header.destination = u64::from_be_bytes(fixed[24..32].try_into().expect("fixed length"));
    header.previous_hop = u64::from_be_bytes(fixed[32..40].try_into().expect("fixed length"));
    header.next_hop = u64::from_be_bytes(fixed[40..48].try_into().expect("fixed length"));
    header.message.session = u32::from_be_bytes(fixed[48..52].try_into().expect("fixed length"));
    header.message.sequence = u64::from_be_bytes(fixed[52..60].try_into().expect("fixed length"));
    header.remaining_deadline_ms =
        u32::from_be_bytes(fixed[60..64].try_into().expect("fixed length"));
    header.original_lifetime_ms =
        u32::from_be_bytes(fixed[64..68].try_into().expect("fixed length"));
    header.link_epoch = u32::from_be_bytes(fixed[68..72].try_into().expect("fixed length"));
    header.end_epoch = u32::from_be_bytes(fixed[72..76].try_into().expect("fixed length"));
    header.link_counter = read_u48(&fixed[76..82]);
    header.end_counter = read_u48(&fixed[82..88]);
    validate_header(header)
}

/// End-to-end AAD covers only the end-immutable fields of semantics.json
/// (network, origin, message session+sequence, bound destination, delivery
/// contract, flags, original lifetime, payload length) plus version, end epoch
/// (u32) and end counter (u48) — 53 bytes in the same order as the C++
/// `make_end_aad` (protocol/semantics.json `end_aad_fields`).
/// Hop-mutable fields (previous/next hop, hop remaining, delivery round,
/// remaining deadline, link epoch/counter) must never be added here.
fn end_aad(header: &Header) -> [u8; 53] {
    let mut aad = [0_u8; 53];
    aad[0] = MAJOR;
    aad[1] = MINOR;
    aad[2] = header.frame_type as u8;
    aad[3] = header.flags;
    aad[4] = header.delivery as u8;
    aad[5..9].copy_from_slice(&(header.network as u32).to_be_bytes());
    aad[9..17].copy_from_slice(&header.origin.to_be_bytes());
    aad[17..25].copy_from_slice(&header.destination.to_be_bytes());
    aad[25..29].copy_from_slice(&header.message.session.to_be_bytes());
    aad[29..37].copy_from_slice(&header.message.sequence.to_be_bytes());
    aad[37..41].copy_from_slice(&header.original_lifetime_ms.to_be_bytes());
    aad[41..45].copy_from_slice(&header.end_epoch.to_be_bytes());
    // validate_header bounds the counter to 48 bits before any AAD is built.
    aad[45..51].copy_from_slice(&header.end_counter.to_be_bytes()[2..8]);
    aad[51..53].copy_from_slice(&header.payload_length.to_be_bytes());
    aad
}

fn link_context(header: &Header) -> SecurityContext {
    SecurityContext {
        scope: SecurityScope::Link,
        network: header.network,
        sender: header.previous_hop,
        receiver: header.next_hop,
        epoch: header.link_epoch,
    }
}

fn end_context(header: &Header) -> SecurityContext {
    // GROUP_DATA is end-protected under the group scope (C++ end_context):
    // the context receiver is the fixed site-group domain, so one key,
    // counter space and replay window per (sender, epoch) cover every group;
    // the destination group stays authenticated through the end AAD.
    let group = header.frame_type == FrameType::GroupData;
    SecurityContext {
        scope: if group {
            SecurityScope::Group
        } else {
            SecurityScope::EndToEnd
        },
        network: header.network,
        sender: header.origin,
        receiver: if group {
            BROADCAST_NODE_ID
        } else {
            header.destination
        },
        epoch: header.end_epoch,
    }
}

fn wrap_link<S: SecurityProvider>(
    header: &Header,
    link_plaintext: &[u8],
    security: &mut S,
    output: &mut EncodedFrame,
) -> Result<()> {
    let total = HEADER_SIZE + link_plaintext.len() + AEAD_TAG_SIZE;
    if total > output.bytes.len() {
        return err(
            ErrorCode::NoCapacity,
            "encoded frame exceeds ESP-NOW v1 body",
        );
    }
    let mut header_bytes = [0_u8; HEADER_SIZE];
    write_header(header, &mut header_bytes)?;
    let tag = security.seal(
        &link_context(header),
        header.link_counter,
        &header_bytes,
        link_plaintext,
        &mut output.bytes[HEADER_SIZE..HEADER_SIZE + link_plaintext.len()],
    )?;
    output.bytes[..HEADER_SIZE].copy_from_slice(&header_bytes);
    output.bytes[HEADER_SIZE + link_plaintext.len()..total].copy_from_slice(&tag);
    output.size = total;
    Ok(())
}

pub fn validate_header(header: &Header) -> Result<()> {
    // frame_type/delivery are enums, so the decoder's unknown-type and
    // delivery-class rejections cannot be bypassed at the API boundary: an
    // invalid value is unconstructable here (unlike the C++ u8 fields).
    if header.network == 0
        || header.network > u64::from(u32::MAX)
        || header.origin == INVALID_NODE_ID
        || header.destination == INVALID_NODE_ID
        || header.previous_hop == INVALID_NODE_ID
        || header.next_hop == INVALID_NODE_ID
    {
        return err(ErrorCode::InvalidArgument, "wire identity field is invalid");
    }
    if header.payload_length > MAX_APPLICATION_PAYLOAD as u16 {
        return err(ErrorCode::InvalidArgument, "payload exceeds v1 limit");
    }
    if header.hop_remaining == 0 && header.destination != header.next_hop {
        return err(
            ErrorCode::InvalidArgument,
            "hop budget exhausted before destination",
        );
    }
    if header.flags & !FLAG_END_PROTECTED != 0 {
        return err(ErrorCode::ProtocolError, "unknown wire flags");
    }
    if header.link_counter > MAX_CRYPTO_COUNTER || header.end_counter > MAX_CRYPTO_COUNTER {
        return err(ErrorCode::InvalidArgument, "crypto counter exceeds 48 bits");
    }
    if header.original_lifetime_ms == 0
        || header.remaining_deadline_ms > header.original_lifetime_ms
    {
        return err(ErrorCode::InvalidArgument, "invalid lifetime");
    }
    Ok(())
}

pub fn encode_new<S: SecurityProvider>(
    input: &PlainFrame,
    security: &mut S,
    output: &mut EncodedFrame,
) -> Result<()> {
    if !security.ready() {
        return err(ErrorCode::InvalidState, "security provider is not ready");
    }
    if input.payload_size > MAX_APPLICATION_PAYLOAD {
        return err(ErrorCode::InvalidArgument, "application payload too large");
    }

    let mut header = input.header.clone();
    header.payload_length = input.payload_size as u16;
    validate_header(&header)?;

    header.link_counter = security.next_counter(&link_context(&header))?;

    let mut link_plaintext = [0_u8; MAX_APPLICATION_PAYLOAD + AEAD_TAG_SIZE];
    let mut link_plaintext_size = input.payload_size;

    if header.flags & FLAG_END_PROTECTED != 0 {
        header.end_counter = security.next_counter(&end_context(&header))?;
        let aad = end_aad(&header);
        let end_tag = security.seal(
            &end_context(&header),
            header.end_counter,
            &aad,
            &input.payload[..input.payload_size],
            &mut link_plaintext[..input.payload_size],
        )?;
        link_plaintext[input.payload_size..input.payload_size + AEAD_TAG_SIZE]
            .copy_from_slice(&end_tag);
        link_plaintext_size += AEAD_TAG_SIZE;
    } else {
        link_plaintext[..input.payload_size].copy_from_slice(&input.payload[..input.payload_size]);
    }

    wrap_link(
        &header,
        &link_plaintext[..link_plaintext_size],
        security,
        output,
    )
}

pub fn open_link<S: SecurityProvider>(
    encoded: &[u8],
    local_node: u64,
    security: &mut S,
    output: &mut LinkOpenedFrame,
) -> Result<()> {
    let mut header = Header::default();
    read_header(encoded, &mut header)?;
    if header.next_hop != local_node {
        return err(
            ErrorCode::AuthorizationFailed,
            "frame is not addressed to this hop",
        );
    }
    let expected_plain = usize::from(header.payload_length)
        + if header.flags & FLAG_END_PROTECTED != 0 {
            AEAD_TAG_SIZE
        } else {
            0
        };
    let expected_total = HEADER_SIZE + expected_plain + AEAD_TAG_SIZE;
    if encoded.len() != expected_total || expected_plain > output.protected_payload.len() {
        return err(ErrorCode::ProtocolError, "wire length mismatch");
    }
    let mut tag = [0_u8; AEAD_TAG_SIZE];
    tag.copy_from_slice(&encoded[HEADER_SIZE + expected_plain..expected_total]);
    security.open(
        &link_context(&header),
        header.link_counter,
        &encoded[..HEADER_SIZE],
        &encoded[HEADER_SIZE..HEADER_SIZE + expected_plain],
        &tag,
        &mut output.protected_payload[..expected_plain],
    )?;
    output.header = header;
    output.protected_payload_size = expected_plain;
    Ok(())
}

pub fn open_end<S: SecurityProvider>(
    input: &LinkOpenedFrame,
    local_node: u64,
    security: &mut S,
    output: &mut PlainFrame,
) -> Result<()> {
    if input.header.destination != local_node {
        return err(
            ErrorCode::AuthorizationFailed,
            "end payload is not addressed to this node",
        );
    }
    if input.header.frame_type == FrameType::GroupData {
        return err(
            ErrorCode::AuthorizationFailed,
            "group frame requires open_group",
        );
    }
    // Callers may build LinkOpenedFrame directly (open_link validates these,
    // but the fields are public): reject sizes that cannot fit the fixed
    // buffers before any length arithmetic or slicing.
    if input.header.payload_length > MAX_APPLICATION_PAYLOAD as u16
        || input.protected_payload_size > input.protected_payload.len()
    {
        return err(ErrorCode::ProtocolError, "frame field out of range");
    }
    *output = PlainFrame::default();
    output.header = input.header.clone();
    output.payload_size = usize::from(input.header.payload_length);

    if input.header.flags & FLAG_END_PROTECTED == 0 {
        // Link-only frame: the wire layer accepts the plain payload —
        // whether unprotected DATA is admissible is a delivery-layer
        // policy, not a wire-codec invariant (see the C++ open_end).
        if input.protected_payload_size != usize::from(input.header.payload_length) {
            return err(
                ErrorCode::ProtocolError,
                "plain control payload length mismatch",
            );
        }
        output.payload[..output.payload_size]
            .copy_from_slice(&input.protected_payload[..output.payload_size]);
        return Ok(());
    }

    if input.protected_payload_size != usize::from(input.header.payload_length) + AEAD_TAG_SIZE {
        return err(
            ErrorCode::ProtocolError,
            "protected payload length mismatch",
        );
    }
    let aad = end_aad(&input.header);
    let mut end_tag = [0_u8; AEAD_TAG_SIZE];
    end_tag.copy_from_slice(
        &input.protected_payload
            [usize::from(input.header.payload_length)..input.protected_payload_size],
    );
    security.open(
        &end_context(&input.header),
        input.header.end_counter,
        &aad,
        &input.protected_payload[..usize::from(input.header.payload_length)],
        &end_tag,
        &mut output.payload[..output.payload_size],
    )
}

/// Opens the group end layer of a link-opened GROUP_DATA frame (C++
/// `wire::open_group`): any group key holder may call it — there is no
/// binding to the local node, and success proves membership of the sealer,
/// never the origin's identity.
pub fn open_group<S: SecurityProvider>(
    input: &LinkOpenedFrame,
    security: &mut S,
    output: &mut PlainFrame,
) -> Result<()> {
    if input.header.frame_type != FrameType::GroupData
        || input.header.flags & FLAG_END_PROTECTED == 0
        || !group::is_group_address(input.header.destination)
    {
        return err(ErrorCode::AuthorizationFailed, "not a group frame");
    }
    if input.header.payload_length > MAX_APPLICATION_PAYLOAD as u16
        || input.protected_payload_size > input.protected_payload.len()
        || input.protected_payload_size != usize::from(input.header.payload_length) + AEAD_TAG_SIZE
    {
        return err(
            ErrorCode::ProtocolError,
            "protected payload length mismatch",
        );
    }
    *output = PlainFrame::default();
    output.header = input.header.clone();
    output.payload_size = usize::from(input.header.payload_length);
    let aad = end_aad(&input.header);
    let mut end_tag = [0_u8; AEAD_TAG_SIZE];
    end_tag.copy_from_slice(
        &input.protected_payload
            [usize::from(input.header.payload_length)..input.protected_payload_size],
    );
    security.open(
        &end_context(&input.header),
        input.header.end_counter,
        &aad,
        &input.protected_payload[..usize::from(input.header.payload_length)],
        &end_tag,
        &mut output.payload[..output.payload_size],
    )
}

pub fn forward<S: SecurityProvider>(
    input: &LinkOpenedFrame,
    local_node: u64,
    next_hop: u64,
    link_epoch: u32,
    remaining_deadline_ms: u32,
    security: &mut S,
    output: &mut EncodedFrame,
) -> Result<()> {
    // next_hop == destination is the normal final hop — only the invalid
    // sentinel and self-forwarding are rejected here.
    if input.header.next_hop != local_node
        || input.header.destination == local_node
        || next_hop == INVALID_NODE_ID
        || next_hop == local_node
    {
        return err(
            ErrorCode::InvalidState,
            "frame is not forwardable by this node",
        );
    }
    // Same defensive bounds as open_end: the fields are public and must be
    // consistent before the protected bytes are re-wrapped.
    let expected_plain = usize::from(input.header.payload_length)
        + if input.header.flags & FLAG_END_PROTECTED != 0 {
            AEAD_TAG_SIZE
        } else {
            0
        };
    if input.header.payload_length > MAX_APPLICATION_PAYLOAD as u16
        || input.protected_payload_size != expected_plain
    {
        return err(ErrorCode::ProtocolError, "frame field out of range");
    }
    if input.header.hop_remaining <= 1 || remaining_deadline_ms == 0 {
        return err(ErrorCode::Expired, "forwarding budget exhausted");
    }
    let mut header = input.header.clone();
    header.previous_hop = local_node;
    header.next_hop = next_hop;
    // The link context keys on (previous_hop, next_hop, link_epoch): with
    // boot-advancing epochs the origin's epoch differs from the forwarder's,
    // so the outgoing hop MUST be stamped with OUR epoch — inheriting the
    // incoming one would wedge the downstream link floor either direction.
    header.link_epoch = link_epoch;
    header.hop_remaining -= 1;
    header.remaining_deadline_ms = remaining_deadline_ms.min(header.remaining_deadline_ms);
    header.link_counter = security.next_counter(&link_context(&header))?;
    wrap_link(
        &header,
        &input.protected_payload[..input.protected_payload_size],
        security,
        output,
    )
}
