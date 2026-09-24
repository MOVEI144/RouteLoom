//! GrantRenew type 7 and SAK-signed CutoverCommit wire. No Host production
//! cutover API is enabled here: a signer can build test-only device fixtures.
use routeloom_provision::sdkv1::cert::CERT_MAX;
use routeloom_provision::sdkv1::{
    cose_es256_assemble, cose_es256_parse, cose_es256_sign, cose_es256_verify,
};
use routeloom_provision::signer::RootSigner;
use routeloom_provision::{Code, Error, Result};

const DOMAIN: &[u8] = b"RouteLoom/site-cutover/v1\0";
pub const COMMIT_PAYLOAD_SIZE: usize = 80;
pub const COMMIT_OBJECT_SIZE: usize = 155;
pub const HEAD_SIZE: usize = 24;
pub const RECEIPT_SIZE: usize = 76;
pub const PREPARE_MAX: usize = 700;
pub const COMMIT_MAX: usize = 799;

fn invalid(message: &'static str) -> Error {
    Error::new(Code::ProtocolError, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Prepare = 1,
    Commit = 2,
    Prepared = 3,
    Applied = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Head {
    pub phase: Phase,
    pub cutover_id: u64,
    pub revision: u32,
    pub old_network: u64,
}
impl Head {
    pub fn encode(self) -> Result<[u8; HEAD_SIZE]> {
        if self.cutover_id == 0 || self.revision == 0 || self.old_network == 0 {
            return Err(invalid("renew head"));
        }
        let mut out = [0; HEAD_SIZE];
        out[0] = 1;
        out[1] = self.phase as u8;
        out[4..12].copy_from_slice(&self.cutover_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.revision.to_be_bytes());
        out[16..24].copy_from_slice(&self.old_network.to_be_bytes());
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEAD_SIZE || bytes[0] != 1 || bytes[2..4] != [0, 0] {
            return Err(invalid("renew head"));
        }
        let phase = match bytes[1] {
            1 => Phase::Prepare,
            2 => Phase::Commit,
            3 => Phase::Prepared,
            4 => Phase::Applied,
            _ => return Err(invalid("renew phase")),
        };
        let result = Self {
            phase,
            cutover_id: u64::from_be_bytes(bytes[4..12].try_into().unwrap()),
            revision: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
            old_network: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        };
        result.encode()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prepare<'a> {
    pub head: Head,
    pub new_network: u64,
    pub site_cert: &'a [u8],
    pub member_cert: &'a [u8],
    pub site_package: &'a [u8],
    pub dams: [u8; 32],
}
impl Prepare<'_> {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.head.phase != Phase::Prepare
            || self.new_network >> 32
                != (self.head.old_network >> 32)
                    .checked_add(1)
                    .ok_or_else(|| invalid("epoch exhausted"))?
            || self.new_network as u32 != self.head.old_network as u32
            || self.site_cert.is_empty()
            || self.site_cert.len() > CERT_MAX
            || self.member_cert.is_empty()
            || self.member_cert.len() > CERT_MAX
            || self.site_package.len() != 120
            || !self.dams.iter().any(|v| *v != 0)
        {
            return Err(invalid("renew prepare"));
        }
        let mut out = Vec::with_capacity(PREPARE_MAX);
        out.extend_from_slice(&self.head.encode()?);
        out.extend_from_slice(&self.new_network.to_be_bytes());
        out.extend_from_slice(&(self.site_cert.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.member_cert.len() as u16).to_be_bytes());
        out.extend_from_slice(self.site_cert);
        out.extend_from_slice(self.member_cert);
        out.extend_from_slice(self.site_package);
        out.extend_from_slice(&self.dams);
        if out.len() > PREPARE_MAX {
            return Err(invalid("renew prepare length"));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit<'a> {
    pub head: Head,
    pub proof: &'a [u8],
    pub rrs: &'a [u8],
}
impl Commit<'_> {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.head.phase != Phase::Commit
            || self.proof.len() != COMMIT_OBJECT_SIZE
            || self.rrs.is_empty()
            || self.rrs.len() > 616
        {
            return Err(invalid("renew commit"));
        }
        let mut out = Vec::with_capacity(COMMIT_MAX);
        out.extend_from_slice(&self.head.encode()?);
        out.extend_from_slice(&(self.proof.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.rrs.len() as u16).to_be_bytes());
        out.extend_from_slice(self.proof);
        out.extend_from_slice(self.rrs);
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub head: Head,
    pub new_network: u64,
    pub gk_epoch: u32,
    pub rs_epoch: u32,
    pub digest: [u8; 32],
    pub status: u8,
}
impl Receipt {
    pub fn encode(&self) -> Result<[u8; RECEIPT_SIZE]> {
        if !matches!(self.head.phase, Phase::Prepared | Phase::Applied)
            || self.new_network == 0
            || self.status > 4
            || (self.head.phase == Phase::Prepared && self.rs_epoch != 0)
        {
            return Err(invalid("renew receipt"));
        }
        let mut out = [0; RECEIPT_SIZE];
        out[..24].copy_from_slice(&self.head.encode()?);
        out[24..32].copy_from_slice(&self.new_network.to_be_bytes());
        out[32..36].copy_from_slice(&self.gk_epoch.to_be_bytes());
        out[36..40].copy_from_slice(&self.rs_epoch.to_be_bytes());
        out[40..72].copy_from_slice(&self.digest);
        out[72] = self.status;
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECEIPT_SIZE || bytes[73..] != [0, 0, 0] {
            return Err(invalid("renew receipt"));
        }
        let result = Self {
            head: Head::decode(bytes)?,
            new_network: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            gk_epoch: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
            rs_epoch: u32::from_be_bytes(bytes[36..40].try_into().unwrap()),
            digest: bytes[40..72].try_into().unwrap(),
            status: bytes[72],
        };
        result.encode()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverCommit {
    pub site_id: u64,
    pub old_network: u64,
    pub new_network: u64,
    pub cutover_id: u64,
    pub revision: u32,
    pub gk_epoch: u32,
    pub rs_epoch: u32,
    pub rrs_sha256: [u8; 32],
}
impl CutoverCommit {
    pub fn aad(network: u64) -> Vec<u8> {
        let mut aad = DOMAIN.to_vec();
        aad.extend_from_slice(&network.to_be_bytes());
        aad
    }
    pub fn payload(&self) -> Result<[u8; COMMIT_PAYLOAD_SIZE]> {
        if self.site_id == 0
            || self.old_network == 0
            || self.new_network == 0
            || self.cutover_id == 0
            || self.revision == 0
            || self.gk_epoch == 0
            || self.rs_epoch == 0
        {
            return Err(invalid("cutover binding"));
        }
        let mut out = [0; COMMIT_PAYLOAD_SIZE];
        out[0] = 1;
        out[4..12].copy_from_slice(&self.site_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.old_network.to_be_bytes());
        out[20..28].copy_from_slice(&self.new_network.to_be_bytes());
        out[28..36].copy_from_slice(&self.cutover_id.to_be_bytes());
        out[36..40].copy_from_slice(&self.revision.to_be_bytes());
        out[40..44].copy_from_slice(&self.gk_epoch.to_be_bytes());
        out[44..48].copy_from_slice(&self.rs_epoch.to_be_bytes());
        out[48..80].copy_from_slice(&self.rrs_sha256);
        Ok(out)
    }
    pub fn issue(&self, sak: &dyn RootSigner) -> Result<Vec<u8>> {
        let payload = self.payload()?;
        let sig = cose_es256_sign(sak, &payload, &Self::aad(self.old_network))?;
        Ok(cose_es256_assemble(&payload, &sig))
    }
    pub fn verify(object: &[u8], sak: &[u8; 64], old_network: u64) -> Result<(Self, bool)> {
        let parts = cose_es256_parse(
            object,
            COMMIT_PAYLOAD_SIZE,
            COMMIT_PAYLOAD_SIZE,
            COMMIT_OBJECT_SIZE,
        )?;
        let p = parts.payload;
        if object.len() != COMMIT_OBJECT_SIZE || p[0] != 1 || p[1..4] != [0, 0, 0] {
            return Err(invalid("cutover shape"));
        }
        let result = Self {
            site_id: u64::from_be_bytes(p[4..12].try_into().unwrap()),
            old_network: u64::from_be_bytes(p[12..20].try_into().unwrap()),
            new_network: u64::from_be_bytes(p[20..28].try_into().unwrap()),
            cutover_id: u64::from_be_bytes(p[28..36].try_into().unwrap()),
            revision: u32::from_be_bytes(p[36..40].try_into().unwrap()),
            gk_epoch: u32::from_be_bytes(p[40..44].try_into().unwrap()),
            rs_epoch: u32::from_be_bytes(p[44..48].try_into().unwrap()),
            rrs_sha256: p[48..80].try_into().unwrap(),
        };
        result.payload()?;
        Ok((
            result.clone(),
            result.old_network == old_network
                && cose_es256_verify(p, &Self::aad(old_network), &parts.signature, sak),
        ))
    }
}
