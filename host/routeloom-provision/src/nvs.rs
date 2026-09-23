//! The manufactured NVS blob set — P-A1 (`04-provisioning-lifecycle.md`
//! §4.4): the provisioning host emits a complete `rltrust`/`rlcred`/
//! `rlboot` set of NVS entries carrying the same record encodings the
//! device would write — the record format is the contract, not the tool.
//! Written during flash programming via an NVS-partition image or a
//! first-boot injector; this module emits the entry set and a JSON
//! descriptor, and the file layout is the CLI's concern.
//!
//! NVS read-back semantics mirrored from `nvs_config_store.cpp`: a blob is
//! stored at exactly `used_len` (never slot-padded); a missing key reads
//! back uniformly erased and classifies as *never written*. So the emitted
//! blobs are `used_len` bytes — padding to a full slot would still boot
//! (the record head bounds `used_len`) but would not be the bytes the
//! device's own write path produces.
//!
//! Slot policy for a manufactured set:
//! - `rltrust` `t0`/`t1` get the SAME committed record — the
//!   recover()-style twin pair: the boot classifier sees two identical
//!   valid slots and adopts cleanly, and a later single-slot failure still
//!   leaves a verifiable sibling.
//! - `rlcred` `d0`/`d1` likewise carry the identical committed credential
//!   record (RLC1 has no ordinal; identical twins are the only clean
//!   two-valid-slots state). With no credential, the namespace simply has
//!   no entries — a missing blob is the honest fresh state.
//! - `rlboot` `session` is a u32 (the device's `next_boot_session`
//!   counter): `0` makes the first boot run as session 1.

use crate::credential::{
    credential_record_encode, DeviceCredential, CREDENTIAL_SLOT_BYTES, CRED_SEAL_COMMITTED,
};
use crate::image::{image_encode, TrustImage, TRUST_SEAL_COMMITTED, TRUST_STORE_SLOT_BYTES};
use crate::signer::hex_encode;
use crate::Result;

/// NVS namespace for the dual-slot trust store (§4.2.2).
pub const NVS_NAMESPACE_TRUST: &str = "rltrust";
/// NVS namespace for the dual-slot device credential record.
pub const NVS_NAMESPACE_CRED: &str = "rlcred";
/// NVS namespace for the u32 boot session counter.
pub const NVS_NAMESPACE_BOOT: &str = "rlboot";
/// `rltrust` slot keys, in slot order.
pub const NVS_TRUST_KEYS: [&str; 2] = ["t0", "t1"];
/// `rlcred` slot keys, in slot order.
pub const NVS_CRED_KEYS: [&str; 2] = ["d0", "d1"];
/// `rlboot` u32 key (see `next_boot_session` in the reference node).
pub const NVS_BOOT_KEY_SESSION: &str = "session";

/// The descriptor document's format marker.
pub const NVS_SET_FORMAT: &str = "routeloom-manufactured-nvs-v1";

/// One NVS entry's value: either a blob (written as raw bytes) or a u32
/// (the `rlboot` counter — written via `nvs_set_u32` semantics, NOT a
/// blob; the `data` form is the little-endian u32 for injectors that need
/// a file).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NvsValue {
    Blob(Vec<u8>),
    U32(u32),
}

/// One manufactured NVS entry — `namespace`/`key` name it exactly as the
/// device's adapters do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NvsEntry {
    pub namespace: &'static str,
    pub key: &'static str,
    pub value: NvsValue,
}

impl NvsEntry {
    /// The bytes a raw file form carries: the blob's `used_len` bytes, or
    /// the u32 little-endian (the NVS entry data layout) for the counter.
    pub fn bytes(&self) -> Vec<u8> {
        match &self.value {
            NvsValue::Blob(blob) => blob.clone(),
            NvsValue::U32(value) => value.to_le_bytes().to_vec(),
        }
    }

    /// Slot capacity for blob entries (None for the u32 counter).
    pub fn slot_bytes(&self) -> Option<usize> {
        match self.namespace {
            NVS_NAMESPACE_TRUST => Some(TRUST_STORE_SLOT_BYTES),
            NVS_NAMESPACE_CRED => Some(CREDENTIAL_SLOT_BYTES),
            crate::sdkv1::rlsec::NVS_NAMESPACE_IDENTITY => {
                Some(crate::sdkv1::identity::IDENTITY_SLOT_BYTES)
            }
            _ => None,
        }
    }

    /// A stable file name for the entry's raw form (the CLI's convention —
    /// `rltrust_t0.bin`, `rlboot_session.u32`).
    pub fn file_name(&self) -> String {
        let extension = match &self.value {
            NvsValue::Blob(_) => "bin",
            NvsValue::U32(_) => "u32",
        };
        format!("{}_{}.{extension}", self.namespace, self.key)
    }
}

/// ESP-IDF `nvs_partition_gen.py` input for `entries`: one `namespace` row
/// whenever the namespace changes, blobs as `file,binary` rows naming
/// [`NvsEntry::file_name`] (the generator resolves relative paths against
/// its working directory — run it from the directory holding the files),
/// u32 values inline. Keys and namespaces are the adapters' exact names.
pub fn nvs_partition_csv(entries: &[NvsEntry]) -> String {
    let mut out = String::from("key,type,encoding,value\n");
    let mut namespace: Option<&str> = None;
    for entry in entries {
        if namespace != Some(entry.namespace) {
            out.push_str(&format!("{},namespace,,\n", entry.namespace));
            namespace = Some(entry.namespace);
        }
        match &entry.value {
            NvsValue::Blob(_) => out.push_str(&format!(
                "{},file,binary,{}\n",
                entry.key,
                entry.file_name()
            )),
            NvsValue::U32(value) => out.push_str(&format!("{},data,u32,{value}\n", entry.key)),
        }
    }
    out
}

/// The complete manufactured set, in deterministic emission order:
/// rltrust t0/t1, rlcred d0/d1 (when a credential is provisioned),
/// rlboot session.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManufacturedNvs {
    pub entries: Vec<NvsEntry>,
}

impl ManufacturedNvs {
    /// The JSON descriptor (`routeloom-manufactured-nvs-v1`) — namespace,
    /// key, entry type, slot capacity and hex bytes per entry, so an
    /// NVS-partition generator or first-boot injector has the full picture
    /// without re-deriving anything.
    pub fn descriptor_json(&self) -> String {
        let mut out = format!("{{\n  \"format\": \"{NVS_SET_FORMAT}\",\n  \"entries\": [");
        for (i, entry) in self.entries.iter().enumerate() {
            out.push_str(if i == 0 { "\n" } else { ",\n" });
            match &entry.value {
                NvsValue::Blob(blob) => out.push_str(&format!(
                    "    {{\"namespace\": \"{}\", \"key\": \"{}\", \"type\": \"blob\", \"slot_bytes\": {}, \"data_hex\": \"{}\"}}",
                    entry.namespace,
                    entry.key,
                    entry.slot_bytes().unwrap_or(0),
                    hex_encode(blob),
                )),
                NvsValue::U32(value) => out.push_str(&format!(
                    "    {{\"namespace\": \"{}\", \"key\": \"{}\", \"type\": \"u32\", \"value\": {}}}",
                    entry.namespace, entry.key, value,
                )),
            }
        }
        out.push_str("\n  ]\n}\n");
        out
    }
}

/// Manufacture the P-A1 blob set for a first install:
/// - `image` is encoded once as a committed RLT1 record and lands in BOTH
///   `rltrust` slots (the twin-pair a clean adopt expects).
/// - `credential`, when provided, is encoded once as a committed RLC1
///   record and lands in both `rlcred` slots. `None` emits no rlcred
///   entries — the honest "no credential yet" state a missing blob means.
/// - `boot_session_stored` is the persisted `rlboot`/`session` value: the
///   device's `next_boot_session` returns `stored + 1`, so `0` starts the
///   first boot at session 1. For a manufactured credential its
///   `generation_base_session` must be <= the first real session the
///   device will run — `0` is the only always-safe manufactured value.
///
/// Both encoders validate first — a set that cannot boot-validate is
/// never emitted.
pub fn manufacture_nvs_set(
    image: &TrustImage,
    credential: Option<&DeviceCredential>,
    boot_session_stored: u32,
) -> Result<ManufacturedNvs> {
    let mut set = ManufacturedNvs::default();
    let trust_record = image_encode(image, TRUST_SEAL_COMMITTED)?;
    for key in NVS_TRUST_KEYS {
        set.entries.push(NvsEntry {
            namespace: NVS_NAMESPACE_TRUST,
            key,
            value: NvsValue::Blob(trust_record.clone()),
        });
    }
    if let Some(credential) = credential {
        let record = credential_record_encode(credential, CRED_SEAL_COMMITTED)?;
        for key in NVS_CRED_KEYS {
            set.entries.push(NvsEntry {
                namespace: NVS_NAMESPACE_CRED,
                key,
                value: NvsValue::Blob(record.clone()),
            });
        }
    }
    set.entries.push(NvsEntry {
        namespace: NVS_NAMESPACE_BOOT,
        key: NVS_BOOT_KEY_SESSION,
        value: NvsValue::U32(boot_session_stored),
    });
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{
        credential_record_decode, grant_fixture, CredStatus, DeviceCredential, KeyLocation,
        CREDENTIAL_SLOT_BYTES,
    };
    use crate::image::{
        image_decode, AnchorStatus, KeyStatus, TrustAnchor, TrustImage, TrustKeyRecord,
    };
    use crate::signer::test_keypair;

    fn image() -> TrustImage {
        let (_, root_pub) = test_keypair(0x11);
        let (_, auth_pub) = test_keypair(0x33);
        let mut image = TrustImage {
            store_epoch: 1,
            min_authority_generation: 1,
            network: 7,
            deployment_id: 0xDE9,
            ..TrustImage::default()
        };
        image.anchors.push(TrustAnchor {
            root_id: 0x100,
            pubkey: root_pub,
            status: AnchorStatus::Active,
        });
        image.keys.push(TrustKeyRecord {
            authority_id: 0xA17,
            generation: 1,
            profile: 1,
            role: 1,
            status: KeyStatus::Active,
            scope: 0,
            pubkey: auth_pub,
        });
        image
    }

    fn credential() -> DeviceCredential {
        let (secret, pubkey) = test_keypair(0x55);
        let kid = crate::credential::credential_kid(&pubkey);
        DeviceCredential {
            network: 7,
            node_id: 0xC3,
            generation_base_session: 0,
            key_location: KeyLocation::NvsPlaintext,
            cred_status: CredStatus::Active,
            kid,
            pubkey,
            key_material: secret,
            grant: grant_fixture(7, 0xC3, &kid, 3, 7, 11, 1000, 2000),
        }
    }

    #[test]
    fn manufactured_set_layout() {
        let set = manufacture_nvs_set(&image(), Some(&credential()), 0).unwrap();
        assert_eq!(set.entries.len(), 5);
        assert_eq!(set.entries[0].namespace, "rltrust");
        assert_eq!(set.entries[0].key, "t0");
        assert_eq!(set.entries[1].key, "t1");
        // Twin-pair: identical committed records in both slots.
        assert_eq!(set.entries[0].value, set.entries[1].value);
        assert_eq!(set.entries[2].namespace, "rlcred");
        assert_eq!(set.entries[2].value, set.entries[3].value);
        assert_eq!(set.entries[4].namespace, "rlboot");
        assert_eq!(set.entries[4].value, NvsValue::U32(0));
        // The trust blobs decode as committed valid RLT1; the credential
        // blobs as committed valid RLC1.
        let NvsValue::Blob(record) = &set.entries[0].value else {
            panic!("blob expected");
        };
        let decoded = image_decode(record).unwrap();
        assert_eq!(decoded.store_epoch, 1);
        // Slot image: blob bytes + erased tail still classify clean.
        let mut slot = vec![0xFF_u8; TRUST_STORE_SLOT_BYTES];
        slot[..record.len()].copy_from_slice(record);
        assert_eq!(image_decode(&slot).unwrap().store_epoch, 1);
        let NvsValue::Blob(cred_record) = &set.entries[2].value else {
            panic!("blob expected");
        };
        let decoded_cred = credential_record_decode(cred_record).unwrap();
        assert_eq!(decoded_cred.node_id, 0xC3);
        let mut cred_slot = vec![0xFF_u8; CREDENTIAL_SLOT_BYTES];
        cred_slot[..cred_record.len()].copy_from_slice(cred_record);
        assert_eq!(credential_record_decode(&cred_slot).unwrap().node_id, 0xC3);
    }

    #[test]
    fn manufactured_without_credential() {
        let set = manufacture_nvs_set(&image(), None, 0).unwrap();
        assert_eq!(set.entries.len(), 3);
        assert!(set.entries.iter().all(|e| e.namespace != "rlcred"));
    }

    #[test]
    fn descriptor_is_parseable_json() {
        let set = manufacture_nvs_set(&image(), Some(&credential()), 0).unwrap();
        let doc = routeloom_json::parse(&set.descriptor_json()).unwrap();
        assert_eq!(
            doc.get("format").and_then(|f| f.as_str()),
            Some(NVS_SET_FORMAT)
        );
        let entries = doc.get("entries").and_then(|e| e.as_array()).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries[0].get("namespace").and_then(|v| v.as_str()),
            Some("rltrust")
        );
        assert_eq!(entries[4].get("type").and_then(|v| v.as_str()), Some("u32"));
        assert_eq!(entries[4].get("value").and_then(|v| v.as_u64()), Some(0));
    }
}
