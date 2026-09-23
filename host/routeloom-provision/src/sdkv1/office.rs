//! Office provisioning (docs/design/sdk-v1/07 §6, 08 P7-1): turning a
//! possession-proven device key and a DevCert into the site-independent RLI1
//! identity, plus the two outputs the office hands on — the bundle a device
//! applies itself (device-generated key) and the inventory line KGuard
//! pre-registers assignments with.
//!
//! Two key paths (07 §6):
//! - **device-generated (default)**: the device creates its key after
//!   entropy is READY and proves possession ([`super::pop`]). The office
//!   never sees the secret, so it cannot write RLI1; it emits an
//!   [`identity_bundle_json`] for the device maintenance verb to seal into
//!   `rlident` itself (firmware follow-up, see 08 P7-1).
//! - **injected (below tier T1, 04 provisioning §4.4)**: the office
//!   generates the key, so it can build the full RLI1
//!   ([`identity_build_injected`]) and the `rlsec` NVS image
//!   ([`super::rlsec`]). The secret then exists in the output files until
//!   they are destroyed — the CLI writes them 0600 and says so.

use crate::credential::{credential_kid, KeyLocation};
use crate::signer::{hex_encode, pubkey_from_secret};
use crate::{err, Code, Result};

use super::cert::{cert_decode, CertType};
use super::identity::{
    identity_validate, AnchorKind, AnchorStatus, IdentityAnchor, IdentityRecord, FLAG_MASK,
};

/// Site-independent inputs for RLI1 besides the key: flags and the Site CA
/// (and, in strict mode A2, assignment verifier) anchors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityPlan {
    pub node_id: u64,
    pub flags: u8,
    pub anchors: Vec<IdentityAnchor>,
}

/// Build the RLI1 record for an office-injected key (`nvs-plaintext`).
/// Every boot check runs here (kid, keypair, anchors, DevCert names this
/// node and key), so the emitted record is one the device adopts.
pub fn identity_build_injected(
    plan: &IdentityPlan,
    secret: &[u8; 32],
    devcert: &[u8],
) -> Result<IdentityRecord> {
    let Some(pubkey) = pubkey_from_secret(secret) else {
        return err(Code::InvalidArgument, "device secret range");
    };
    let record = IdentityRecord {
        node_id: plan.node_id,
        key_location: KeyLocation::NvsPlaintext,
        flags: plan.flags,
        kid: credential_kid(&pubkey),
        pubkey,
        key_material: *secret,
        anchors: plan.anchors.clone(),
        devcert: devcert.to_vec(),
    };
    identity_validate(&record)?;
    Ok(record)
}

fn anchor_kind_name(kind: AnchorKind) -> &'static str {
    match kind {
        AnchorKind::SiteCa => "site-ca",
        AnchorKind::AssignmentVerifier => "assignment-verifier",
    }
}

fn anchor_status_name(status: AnchorStatus) -> &'static str {
    match status {
        AnchorStatus::Active => "active",
        AnchorStatus::Disabled => "disabled",
    }
}

/// Bundle format for the device-generated path.
pub const IDENTITY_BUNDLE_FORMAT: &str = "routeloom-identity-bundle-v1";

/// What the device maintenance verb needs to seal RLI1 around its own key:
/// node id, flags, anchors and the DevCert (whose `cnf` must equal the
/// device's public key — the verb refuses otherwise). No secret inside.
/// Validated with the same rules as RLI1 (minus the key, which only the
/// device holds).
pub fn identity_bundle_json(plan: &IdentityPlan, devcert: &[u8]) -> Result<String> {
    let claims = cert_decode(devcert)?;
    if claims.cert_type != CertType::Device || claims.subject != plan.node_id {
        return err(Code::InvalidArgument, "bundle devcert names another node");
    }
    // Reuse the RLI1 rules by validating a stand-in record with the
    // DevCert's own key and no private material (location none).
    let stand_in = IdentityRecord {
        node_id: plan.node_id,
        key_location: KeyLocation::None,
        flags: plan.flags,
        kid: credential_kid(&claims.pubkey),
        pubkey: claims.pubkey,
        key_material: [0; 32],
        anchors: plan.anchors.clone(),
        devcert: devcert.to_vec(),
    };
    identity_validate(&stand_in)?;
    let anchors: Vec<String> = plan
        .anchors
        .iter()
        .map(|a| {
            format!(
                "    {{\"anchor_id\": \"{:016x}\", \"kind\": \"{}\", \"status\": \"{}\", \"pubkey_hex\": \"{}\"}}",
                a.anchor_id,
                anchor_kind_name(a.kind),
                anchor_status_name(a.status),
                hex_encode(&a.pubkey)
            )
        })
        .collect();
    Ok(format!(
        "{{\n  \"format\": \"{IDENTITY_BUNDLE_FORMAT}\",\n  \"node_id\": \"{:016x}\",\n  \"flags\": {},\n  \"kid_hex\": \"{}\",\n  \"pubkey_hex\": \"{}\",\n  \"anchors\": [\n{}\n  ],\n  \"devcert_hex\": \"{}\"\n}}\n",
        plan.node_id,
        plan.flags & FLAG_MASK,
        hex_encode(&stand_in.kid),
        hex_encode(&claims.pubkey),
        anchors.join(",\n"),
        hex_encode(devcert),
    ))
}

/// One inventory line (07 §6 "在庫出力": `(node_id, kid, model,
/// cert_serial)` for KGuard's assignment pre-registration), as compact
/// JSON. Derived from the DevCert, never from operator input.
pub fn inventory_json(devcert: &[u8]) -> Result<String> {
    let claims = cert_decode(devcert)?;
    if claims.cert_type != CertType::Device {
        return err(Code::InvalidArgument, "inventory needs a devcert");
    }
    Ok(format!(
        "{{\"node_id\":\"{:016x}\",\"kid\":\"{}\",\"model\":{},\"hw_rev\":{},\"cert_serial\":{},\"device_ca_id\":\"{:016x}\"}}",
        claims.subject,
        hex_encode(&credential_kid(&claims.pubkey)),
        claims.model,
        claims.hw_rev,
        claims.serial,
        claims.issuer,
    ))
}
