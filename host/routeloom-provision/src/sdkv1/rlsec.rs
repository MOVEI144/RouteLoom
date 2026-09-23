//! The office-written `rlsec` NVS content (docs/design/sdk-v1/05 §5,
//! 07 §6 "`nvs`: `rlsec` partition image, `rlident` only"). Same approach
//! as the P-A1 [`crate::nvs`] set: the record encoding is the contract, the
//! tool emits the entries (blob files + JSON descriptor) and an ESP-IDF
//! `nvs_partition_gen.py` CSV; the device's NVS adapter
//! (`components/routeloom_espnow` `NvsBlobNamespace` over
//! `sdkv1_blob_storage`) reads exactly these names.
//!
//! `rlsec` layout (mirrors `sdkv1_blob_storage.hpp`):
//!
//! | namespace | keys | content | written by |
//! |---|---|---|---|
//! | `rlident` | `i0`, `i1` | RLI1 twin pair (≤ 664 B each) | office (this module) |
//! | `rlsite` | `s0`, `s1` | RLS1 A/B | device, after join |
//! | `rlrevo` | `r0`, `r1` | RRS1 storage record A/B | device |
//! | `rlres` | `s00`…`s15` (gateway `s000`…`s159`) | RLP1 slots | device |
//!
//! Only `rlident` is manufactured: everything else is site-dependent and
//! arrives through the join (02 §1). Both `rlident` keys carry the same
//! committed record — the twin pair `IdentityStore` adopts cleanly.
//!
//! The image replaces the whole `rlsec` partition (flashing it erases any
//! previous rlcounter/rlreplay state there — the NVS erase accepted in
//! 08 Q13). NVS encryption (tier T2) would use the generator's `encrypt`
//! mode with an `nvs_keys` partition; nothing here burns eFuses or enables
//! flash encryption.

use crate::nvs::{nvs_partition_csv, NvsEntry, NvsValue};
use crate::signer::hex_encode;
use crate::{err, Code, Result};

use super::identity::{
    identity_record_decode, identity_record_encode, IdentityRecord, IDENTITY_SEAL_COMMITTED,
};

/// The dedicated security NVS partition label (`kSecurityNvsPartition`).
pub const RLSEC_PARTITION: &str = "rlsec";
/// Partition sizes in the firmware tables (node 64 KiB, gateway 128 KiB).
pub const RLSEC_NODE_PARTITION_BYTES: u32 = 0x1_0000;
pub const RLSEC_GATEWAY_PARTITION_BYTES: u32 = 0x2_0000;

pub const NVS_NAMESPACE_IDENTITY: &str = "rlident";
pub const NVS_IDENTITY_KEYS: [&str; 2] = ["i0", "i1"];
pub const NVS_NAMESPACE_SITE: &str = "rlsite";
pub const NVS_SITE_KEYS: [&str; 2] = ["s0", "s1"];
pub const NVS_NAMESPACE_REVOCATION: &str = "rlrevo";
pub const NVS_REVOCATION_KEYS: [&str; 2] = ["r0", "r1"];
pub const NVS_NAMESPACE_RESUME: &str = "rlres";
pub const RESUME_NODE_SLOTS: usize = 16;
pub const RESUME_GATEWAY_SLOTS: usize = 160;

/// Descriptor format marker.
pub const RLSEC_SET_FORMAT: &str = "routeloom-rlsec-nvs-v1";

/// Key of resume slot `index` in a cache of `slot_count` slots (`s%02u`
/// up to 100 slots, `s%03u` beyond) — `BlobResumeSlotStorage::slot_key`.
pub fn resume_slot_key(index: usize, slot_count: usize) -> Result<String> {
    if slot_count == 0 || slot_count > 999 || index >= slot_count {
        return err(Code::InvalidArgument, "resume slot index");
    }
    Ok(if slot_count <= 100 {
        format!("s{index:02}")
    } else {
        format!("s{index:03}")
    })
}

/// The manufactured `rlsec` entry set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RlsecNvsSet {
    pub entries: Vec<NvsEntry>,
}

impl RlsecNvsSet {
    /// `routeloom-rlsec-nvs-v1` descriptor: partition, namespace, key,
    /// type, slot capacity and hex bytes per entry. Contains the device
    /// secret for an injected (`nvs-plaintext`) key — handle it like the
    /// blob files.
    pub fn descriptor_json(&self) -> String {
        let mut out = format!(
            "{{\n  \"format\": \"{RLSEC_SET_FORMAT}\",\n  \"partition\": \"{RLSEC_PARTITION}\",\n  \"entries\": ["
        );
        for (i, entry) in self.entries.iter().enumerate() {
            out.push_str(if i == 0 { "\n" } else { ",\n" });
            if let NvsValue::Blob(blob) = &entry.value {
                out.push_str(&format!(
                    "    {{\"namespace\": \"{}\", \"key\": \"{}\", \"type\": \"blob\", \"slot_bytes\": {}, \"file\": \"{}\", \"data_hex\": \"{}\"}}",
                    entry.namespace,
                    entry.key,
                    entry.slot_bytes().unwrap_or(0),
                    entry.file_name(),
                    hex_encode(blob),
                ));
            }
        }
        out.push_str("\n  ]\n}\n");
        out
    }

    /// `nvs_partition_gen.py generate <csv> rlsec.bin <size>` input.
    pub fn partition_csv(&self) -> String {
        nvs_partition_csv(&self.entries)
    }
}

/// `rlident` i0/i1 = the same committed RLI1 record. The encoder
/// validates first, so a set that could not pass the device's boot checks
/// is never emitted.
pub fn rlsec_identity_set(record: &IdentityRecord) -> Result<RlsecNvsSet> {
    let blob = identity_record_encode(record, IDENTITY_SEAL_COMMITTED)?;
    Ok(RlsecNvsSet {
        entries: NVS_IDENTITY_KEYS
            .iter()
            .map(|&key| NvsEntry {
                namespace: NVS_NAMESPACE_IDENTITY,
                key,
                value: NvsValue::Blob(blob.clone()),
            })
            .collect(),
    })
}

/// Read a manufactured set back the way a first boot would: both
/// `rlident` blobs present, byte-identical (twin pair) and decoding as a
/// committed, boot-valid RLI1. Anything else is refused.
pub fn rlsec_identity_readback(set: &RlsecNvsSet) -> Result<IdentityRecord> {
    let blob = |key: &str| {
        set.entries
            .iter()
            .find(|e| e.namespace == NVS_NAMESPACE_IDENTITY && e.key == key)
            .and_then(|e| match &e.value {
                NvsValue::Blob(blob) => Some(blob.as_slice()),
                NvsValue::U32(_) => None,
            })
    };
    let (Some(first), Some(second)) = (blob(NVS_IDENTITY_KEYS[0]), blob(NVS_IDENTITY_KEYS[1]))
    else {
        return err(Code::ProtocolError, "rlident twin missing");
    };
    if first != second {
        return err(Code::IntegrityError, "rlident twins diverge");
    }
    identity_record_decode(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_keys_match_the_device_adapter() {
        assert_eq!(resume_slot_key(0, RESUME_NODE_SLOTS).unwrap(), "s00");
        assert_eq!(resume_slot_key(15, RESUME_NODE_SLOTS).unwrap(), "s15");
        assert_eq!(resume_slot_key(0, RESUME_GATEWAY_SLOTS).unwrap(), "s000");
        assert_eq!(resume_slot_key(159, RESUME_GATEWAY_SLOTS).unwrap(), "s159");
        assert!(resume_slot_key(16, RESUME_NODE_SLOTS).is_err());
        assert!(resume_slot_key(0, 0).is_err());
        assert!(resume_slot_key(0, 1000).is_err());
    }
}
