//! Manual channel plan signed by the Site Authority (V2-08, issue #5
//! manual): byte mirror of the device's `plan_encode`, `plan_digest`,
//! `bind_operation_payload`, `commit_signing_input` and `snapshot_encode`
//! (components/routeloom/src/{migration,migration_wire,authority}.cpp). The
//! SAK signs SHA-256(domain || input) for the commit and the recovery
//! snapshot; the device verifies with `SiteCommitVerifier`
//! (site_signed.hpp). `protocol/site-signed-golden/` pins the bytes.

use crate::sha256::sha256;
use crate::signer::RootSigner;
use crate::{err, Code, Result};

pub const COMMIT_DOMAIN: &[u8] = b"RouteLoom/channel-commit/v1\0";
pub const SNAPSHOT_DOMAIN: &[u8] = b"RouteLoom/channel-snapshot/v1\0";
/// migration_const::kPlanBlobMax / kMaxHelpers.
pub const PLAN_BLOB_MAX: usize = 384;
pub const HELPERS_MAX: usize = 8;
const PLAN_VERSION: u8 = 1;
const SNAPSHOT_VERSION: u8 = 1;
const KIND_CHANNEL_MIGRATION: u8 = 4;

/// The committed recovery schedule (HelperSchedule).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HelperSchedule {
    pub helpers: Vec<u64>,
    pub visit_period_ms: u32,
    pub dwell_ms: u32,
    pub window_begin_ms: u64,
    pub window_end_ms: u64,
    pub object_bytes_max: u16,
}

/// MigrationPlan. Times are in the offering gateway's monotonic domain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChannelPlan {
    pub network: u64,
    pub authority: u64,
    pub authority_generation: u32,
    pub operation_sequence: u64,
    pub previous_state_hash: [u8; 32],
    pub old_epoch: u32,
    pub new_epoch: u32,
    pub old_channel: u8,
    pub new_channel: u8,
    pub participant_capability_mask: u32,
    pub required_participant_digest: [u8; 32],
    pub candidate_evidence_digest: [u8; 32],
    pub authority_session: u64,
    pub switch_reference_ms: u64,
    pub peer_offset_ms: i64,
    pub uncertainty_ms: u32,
    pub expiry_ms: u64,
    pub guard_ms: u32,
    pub recovery: Option<HelperSchedule>,
    pub protected_services_mask: u32,
    pub max_outage_ms: u32,
}

/// Everything a gateway needs to offer the plan: the blob, the operation it
/// commits and the SAK evidence for commit and recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedChannelPlan {
    pub blob: Vec<u8>,
    pub plan_hash: [u8; 32],
    pub operation_hash: [u8; 32],
    pub commit_signature: [u8; 64],
    pub snapshot: Vec<u8>,
    pub snapshot_signature: [u8; 64],
}

pub fn plan_encode(plan: &ChannelPlan) -> Result<Vec<u8>> {
    let empty = HelperSchedule::default();
    let recovery = plan.recovery.as_ref().unwrap_or(&empty);
    if recovery.helpers.len() > HELPERS_MAX {
        return err(Code::InvalidArgument, "helper count overflow");
    }
    let mut out = Vec::with_capacity(PLAN_BLOB_MAX);
    out.push(PLAN_VERSION);
    out.extend_from_slice(&plan.network.to_be_bytes());
    out.extend_from_slice(&plan.authority.to_be_bytes());
    out.extend_from_slice(&plan.authority_generation.to_be_bytes());
    out.extend_from_slice(&plan.operation_sequence.to_be_bytes());
    out.extend_from_slice(&plan.previous_state_hash);
    out.extend_from_slice(&plan.old_epoch.to_be_bytes());
    out.extend_from_slice(&plan.new_epoch.to_be_bytes());
    out.push(plan.old_channel);
    out.push(plan.new_channel);
    out.extend_from_slice(&plan.participant_capability_mask.to_be_bytes());
    out.extend_from_slice(&plan.required_participant_digest);
    out.extend_from_slice(&plan.candidate_evidence_digest);
    out.extend_from_slice(&plan.authority_session.to_be_bytes());
    out.extend_from_slice(&plan.switch_reference_ms.to_be_bytes());
    out.extend_from_slice(&plan.peer_offset_ms.to_be_bytes());
    out.extend_from_slice(&plan.uncertainty_ms.to_be_bytes());
    out.extend_from_slice(&plan.expiry_ms.to_be_bytes());
    out.extend_from_slice(&plan.guard_ms.to_be_bytes());
    out.push(u8::from(plan.recovery.is_some()));
    out.extend_from_slice(&recovery.visit_period_ms.to_be_bytes());
    out.extend_from_slice(&recovery.dwell_ms.to_be_bytes());
    out.extend_from_slice(&recovery.window_begin_ms.to_be_bytes());
    out.extend_from_slice(&recovery.window_end_ms.to_be_bytes());
    out.extend_from_slice(&recovery.object_bytes_max.to_be_bytes());
    out.push(recovery.helpers.len() as u8);
    for helper in &recovery.helpers {
        out.extend_from_slice(&helper.to_be_bytes());
    }
    out.extend_from_slice(&plan.protected_services_mask.to_be_bytes());
    out.extend_from_slice(&plan.max_outage_ms.to_be_bytes());
    if out.len() > PLAN_BLOB_MAX {
        return err(Code::InvalidArgument, "plan blob bound");
    }
    Ok(out)
}

/// The device's deterministic operation binding (authority.cpp); the
/// signature binds the plan through `plan_hash` directly.
fn bind_operation_payload(kind: u8, payload: &[u8]) -> [u8; 32] {
    let mut lanes: [u64; 4] = [
        0x9E37_79B9_7F4A_7C15 ^ (u64::from(kind) + 1),
        0x243F_6A88_85A3_08D3,
        0x4528_21E6_38D0_1377,
        0xBF58_476D_1CE4_E5B9,
    ];
    for (i, byte) in payload.iter().enumerate() {
        let lane = &mut lanes[i % 4];
        *lane ^= u64::from(*byte);
        *lane = lane.wrapping_mul(0x0000_0100_0000_01B3);
        *lane ^= *lane >> 29;
    }
    let mut out = [0_u8; 32];
    for (i, lane) in lanes.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&lane.to_be_bytes());
    }
    out
}

fn operation_fields(plan: &ChannelPlan, operation_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(93);
    out.extend_from_slice(&plan.network.to_be_bytes());
    out.extend_from_slice(&plan.authority.to_be_bytes());
    out.extend_from_slice(&plan.authority_generation.to_be_bytes());
    out.extend_from_slice(&plan.operation_sequence.to_be_bytes());
    out.push(KIND_CHANNEL_MIGRATION);
    out.extend_from_slice(&plan.previous_state_hash);
    out.extend_from_slice(operation_hash);
    out
}

fn sign(sak: &dyn RootSigner, domain: &[u8], input: &[u8]) -> Result<[u8; 64]> {
    let mut message = Vec::with_capacity(domain.len() + input.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(input);
    sak.sign(&message)
}

/// Sign `plan` with the SAK. The plan must name the SAK's site as its
/// authority and move to a new channel under a newer epoch.
pub fn issue(plan: &ChannelPlan, sak: &dyn RootSigner) -> Result<SignedChannelPlan> {
    if plan.authority != sak.root_id() {
        return err(Code::InvalidArgument, "plan authority is not the site");
    }
    if !(1..=13).contains(&plan.new_channel) || plan.new_epoch <= plan.old_epoch {
        return err(Code::InvalidArgument, "plan channel or epoch");
    }
    let blob = plan_encode(plan)?;
    let plan_hash = sha256(&blob);
    let operation_hash = bind_operation_payload(KIND_CHANNEL_MIGRATION, &plan_hash);
    let fields = operation_fields(plan, &operation_hash);

    let mut commit = Vec::with_capacity(6 + fields.len() + 36);
    commit.extend_from_slice(b"RLCMT1");
    commit.extend_from_slice(&fields);
    commit.extend_from_slice(&plan_hash);
    commit.extend_from_slice(&plan.new_epoch.to_be_bytes());
    let commit_signature = sign(sak, COMMIT_DOMAIN, &commit)?;

    let mut snapshot = Vec::with_capacity(2 + fields.len() + 34 + blob.len());
    snapshot.push(SNAPSHOT_VERSION);
    snapshot.push(0);
    snapshot.extend_from_slice(&fields);
    snapshot.extend_from_slice(&plan_hash);
    snapshot.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    snapshot.extend_from_slice(&blob);
    let snapshot_signature = sign(sak, SNAPSHOT_DOMAIN, &snapshot)?;

    Ok(SignedChannelPlan {
        blob,
        plan_hash,
        operation_hash,
        commit_signature,
        snapshot,
        snapshot_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{ecdsa_p256_verify, hex_encode, test_keypair, FileRootSigner};

    // The C++ migration sim's identity (test_migration_wire.cpp: kNet 7,
    // authority 9, helper 5) with the host testkit SAK scalar (0x62).
    const NETWORK: u64 = 7;
    const SITE: u64 = 9;

    fn sak() -> FileRootSigner {
        FileRootSigner::from_secret(SITE, &test_keypair(0x62).0).unwrap()
    }

    // make_plan() in test_migration_wire.cpp: guard = required_guard_ms(10,
    // 50) = 100, validity 120 s past the guard, one helper, 180 s budget.
    fn plan(
        sequence: u64,
        previous: [u8; 32],
        epoch: u32,
        from: u8,
        to: u8,
        at: u64,
    ) -> ChannelPlan {
        ChannelPlan {
            network: NETWORK,
            authority: SITE,
            authority_generation: 1,
            operation_sequence: sequence,
            previous_state_hash: previous,
            old_epoch: epoch - 1,
            new_epoch: epoch,
            old_channel: from,
            new_channel: to,
            participant_capability_mask: 0x3fff,
            authority_session: 42,
            switch_reference_ms: at,
            uncertainty_ms: 10,
            expiry_ms: at + 100 + 120_000,
            guard_ms: 100,
            recovery: Some(HelperSchedule {
                helpers: vec![5],
                visit_period_ms: 5_000,
                dwell_ms: 800,
                window_begin_ms: at,
                window_end_ms: at + 180_000,
                object_bytes_max: 544,
            }),
            protected_services_mask: 1,
            max_outage_ms: 500,
            ..ChannelPlan::default()
        }
    }

    fn golden_json(name: &str, plan: &ChannelPlan, signed: &SignedChannelPlan) -> String {
        format!(
            "{{\n  \"name\":\"{name}\",\n  \"network\":{},\n  \"site_id\":{},\n  \"sak_pubkey_hex\":\"{}\",\
             \n  \"sequence\":{},\n  \"old_epoch\":{},\n  \"new_epoch\":{},\n  \"old_channel\":{},\
             \n  \"new_channel\":{},\n  \"switch_reference_ms\":{},\n  \"previous_state_hex\":\"{}\",\
             \n  \"plan_blob_hex\":\"{}\",\n  \"plan_hash_hex\":\"{}\",\n  \"operation_hash_hex\":\"{}\",\
             \n  \"commit_signature_hex\":\"{}\",\n  \"snapshot_hex\":\"{}\",\n  \"snapshot_signature_hex\":\"{}\"\n}}\n",
            plan.network,
            plan.authority,
            hex_encode(&sak().pubkey()),
            plan.operation_sequence,
            plan.old_epoch,
            plan.new_epoch,
            plan.old_channel,
            plan.new_channel,
            plan.switch_reference_ms,
            hex_encode(&plan.previous_state_hash),
            hex_encode(&signed.blob),
            hex_encode(&signed.plan_hash),
            hex_encode(&signed.operation_hash),
            hex_encode(&signed.commit_signature),
            hex_encode(&signed.snapshot),
            hex_encode(&signed.snapshot_signature),
        )
    }

    #[test]
    fn site_signed_channel_plans_match_golden() {
        // 1 -> 6 at t = 31 s, then back 6 -> 1 once the 10 min cooldown has
        // passed. The gateway ledger's state after a plan is its plan hash,
        // so the back plan chains on the forward plan's hash. Refresh with
        // ROUTELOOM_WRITE_GOLDEN=1; the C++ sim runs the same bytes.
        let forward = plan(1, [0; 32], 1, 1, 6, 31_000);
        let forward_signed = issue(&forward, &sak()).unwrap();
        let back = plan(2, forward_signed.plan_hash, 2, 6, 1, 700_000);
        let back_signed = issue(&back, &sak()).unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/site-signed-golden");
        let write = std::env::var("ROUTELOOM_WRITE_GOLDEN").as_deref() == Ok("1");
        for (name, plan, signed) in [
            ("channel_plan_forward", &forward, &forward_signed),
            ("channel_plan_back", &back, &back_signed),
        ] {
            let digest = sha256(&[COMMIT_DOMAIN, &signed_commit_input(plan, signed)].concat());
            assert!(ecdsa_p256_verify(
                &sak().pubkey(),
                &digest,
                &signed.commit_signature
            ));
            let rendered = golden_json(name, plan, signed);
            let path = dir.join(format!("{name}.json"));
            if write {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &rendered).unwrap();
                continue;
            }
            let checked_in = std::fs::read_to_string(&path).expect("golden checked in");
            assert_eq!(rendered, checked_in.replace("\r\n", "\n"), "{name} drifted");
        }
    }

    fn signed_commit_input(plan: &ChannelPlan, signed: &SignedChannelPlan) -> Vec<u8> {
        let mut input = b"RLCMT1".to_vec();
        input.extend_from_slice(&operation_fields(plan, &signed.operation_hash));
        input.extend_from_slice(&signed.plan_hash);
        input.extend_from_slice(&plan.new_epoch.to_be_bytes());
        input
    }

    #[test]
    fn issue_refuses_a_foreign_authority_and_a_stale_epoch() {
        let mut foreign = plan(1, [0; 32], 1, 1, 6, 31_000);
        foreign.authority = SITE + 1;
        assert!(issue(&foreign, &sak()).is_err());
        let mut stale = plan(1, [0; 32], 1, 1, 6, 31_000);
        stale.new_epoch = stale.old_epoch;
        assert!(issue(&stale, &sak()).is_err());
    }
}
