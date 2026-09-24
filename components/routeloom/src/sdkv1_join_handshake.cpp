// SDK v1 zero-touch join handshake (sdkv1_join_handshake.hpp). One
// Initiator session plus the join EAD/credential plumbing: the EAD hook
// only STAGES bytes — every value it copies is authenticated by the
// session call that owns it, and the m2 gate keeps the DevCert off the
// wire until the SiteCert and the responder signature both checked out.

#include "routeloom/sdkv1_join_handshake.hpp"

#include <cstring>

#include "routeloom/key_schedule.hpp"  // keys::kExporterDams
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {

namespace {

Status malformed(const char* detail) noexcept {
  return Status::error(StatusCode::ProtocolError, detail);
}

bool all_zero(const std::uint8_t* data, const std::size_t size) noexcept {
  std::uint8_t acc = 0;
  for (std::size_t i = 0; i < size; ++i) acc |= data[i];
  return acc == 0;
}

bool id_ok(const std::uint64_t id) noexcept { return id != 0 && id != 0xFFFFFFFFFFFFFFFFULL; }

// EntropySource -> the session's RandomFn (ephemeral scalar + C_I draws).
bool entropy_random(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  auto* entropy = static_cast<EntropySource*>(ctx);
  return entropy->fill(MutableByteView{out, size}).ok();
}

// 02 §10.2 row "generation/role": every role bit beyond endpoint must be
// executable — the JoinRequest capability bits sit at the same positions
// as the role bits (bit1 relay, bit2 gateway).
bool role_executable(const std::uint8_t role, const std::uint32_t capability) noexcept {
  const std::uint32_t needs = role & (kMemberRoleRelay | kMemberRoleGateway);
  return (capability & needs) == needs;
}

bool channel_usable(const std::uint8_t channel, const std::uint16_t mask) noexcept {
  return channel >= 1 && channel <= 14 && ((mask >> channel) & 1U) != 0;
}

}  // namespace

// === EAD token inspection ====================================================

Status join_ead_items_check(const edhoc::EadItem* items, const std::size_t count,
                            const JoinEad expected, const bool need_credential,
                            ByteView& value, ByteView& credential) noexcept {
  value = ByteView{};
  credential = ByteView{};
  bool seen_value = false;
  bool seen_credential = false;
  for (std::size_t i = 0; i < count; ++i) {
    const std::int32_t label = items[i].label;
    if (label == 0) continue;  // padding (RFC 9528 §3.8.1)
    if (label > 0) return malformed("ead non-critical item");
    const std::uint32_t critical = static_cast<std::uint32_t>(-static_cast<std::int64_t>(label));
    if (!seen_value) {
      if (critical != static_cast<std::uint32_t>(expected)) {
        return malformed("ead wrong item");
      }
      if (!join_ead_value_size_ok(expected, items[i].value.size)) {
        return malformed("ead value size");
      }
      value = items[i].value;
      seen_value = true;
      continue;
    }
    if (need_credential && !seen_credential) {
      if (critical != static_cast<std::uint32_t>(JoinEad::Credential)) {
        return malformed("ead credential order");
      }
      if (!join_ead_value_size_ok(JoinEad::Credential, items[i].value.size)) {
        return malformed("ead credential size");
      }
      credential = items[i].value;
      seen_credential = true;
      continue;
    }
    return malformed("ead unexpected item");
  }
  if (!seen_value) return malformed("ead item missing");
  if (need_credential && !seen_credential) return malformed("ead credential missing");
  return Status::success();
}

// === Stored-record re-verification ==========================================

Status join_membership_verify(const SiteRecord& site, const IdentityRecord& identity,
                              bool& verified, const Es256Verifier& verifier) noexcept {
  verified = false;
  Status status = site_validate(site);
  if (!status) return status;
  if (site.state != SiteState::Member) return Status::success();  // cleared: not a membership
  CertClaims site_claims{};
  CertClaims member{};
  status = cert_decode(site.site_cert.view(), site_claims);
  if (status) status = cert_decode(site.member_cert.view(), member);
  if (!status) return status;
  // Binding to this device (02 §10.2 step 2): a record that does not name
  // us parses but does not verify — deny, not a malformed record.
  if (!member_cert_matches(member, site_claims, identity.node_id, identity.pubkey).ok()) {
    return Status::success();
  }
  CertClaims anchored{};
  bool ok = false;
  status = identity_verify_site_cert(identity, site.site_cert.view(), anchored, ok, verifier);
  if (!status) return status;
  if (!ok) return Status::success();
  CertClaims checked{};
  return cert_verify(site.member_cert.view(), site_claims.pubkey, checked, verified, verifier);
}

// === CredentialProvider ======================================================

Status JoinHandshake::Credentials::local(const edhoc::Role, edhoc::LocalCredential& out) noexcept {
  const IdentityRecord& identity = *owner_.identity_;
  out.kid = ByteView{identity.kid.data(), identity.kid.size()};
  out.credential = identity.devcert.view();
  out.private_key = identity.key_material;
  return Status::success();
}

Status JoinHandshake::Credentials::peer(const edhoc::Role, const ByteView kid,
                                        edhoc::PeerCredential& out) noexcept {
  JoinHandshake& o = owner_;
  Status status = [&]() noexcept -> Status {
    if (o.site_cert_.size == 0) {
      return Status::error(StatusCode::NotFound, "no staged site cert");
    }
    CertClaims checked{};
    Status result = join_credential_check(o.site_cert_.view(), CertType::Site, kid, checked);
    if (!result) return result;
    CertClaims claims{};
    bool verified = false;
    result = identity_verify_site_cert(*o.identity_, o.site_cert_.view(), claims, verified);
    if (!result) return result;
    if (!verified) return Status::error(StatusCode::AuthenticationFailed, "site cert chain");
    // The authenticated issuer must be the Site CA the candidate observation
    // named — a certificate of another org does not satisfy this attempt.
    const IdentityAnchor* anchor =
        identity_active_anchor(*o.identity_, claims.issuer, AnchorKind::SiteCa);
    if (anchor == nullptr || join_org_hint(anchor->pubkey) != o.config_.org_hint) {
      return Status::error(StatusCode::AuthenticationFailed, "site ca hint");
    }
    out.credential = o.site_cert_.view();
    out.public_key = claims.pubkey;
    o.site_claims_ = claims;
    return cert_subject_kid(claims, o.sak_kid_);
  }();
  if (!status) ++o.stats_.credential_rejects;
  return status;
}

// === EadHandler ==============================================================

Status JoinHandshake::Ead::compose(const int message, edhoc::EadItem* items,
                                   const std::size_t capacity, std::size_t& count) noexcept {
  count = 0;
  JoinHandshake& o = owner_;
  if (message == 1) {
    if (capacity < 1) return Status::error(StatusCode::NoCapacity, "ead capacity");
    JoinIntent intent{};
    intent.org_hint = o.config_.org_hint;
    intent.profile_bits = kJoinProfileRljoin1;  // P3-5 disabled: no RLRES1 bit
    const Status status = join_intent_encode(intent, o.intent_value_);
    if (!status) return status;
    items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Intent),
                                    o.intent_value_.view()};
    return Status::success();
  }
  if (message == 3) {
    if (capacity < 2) return Status::error(StatusCode::NoCapacity, "ead capacity");
    items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Request),
                                    o.request_value_.view()};
    items[count++] = edhoc::EadItem{-static_cast<std::int32_t>(JoinEad::Credential),
                                    o.identity_->devcert.view()};
    return Status::success();
  }
  return Status::success();
}

Status JoinHandshake::Ead::process(const int message, const edhoc::EadItem* items,
                                   const std::size_t count) noexcept {
  JoinHandshake& o = owner_;
  Status status = Status::error(StatusCode::ProtocolError, "unexpected ead");
  if (message == 2) {
    ByteView offer{};
    ByteView cert{};
    status = join_ead_items_check(items, count, JoinEad::Offer, true, offer, cert);
    if (status) status = site_offer_decode(offer, o.offer_);
    if (status) {
      std::memcpy(o.site_cert_.bytes.data(), cert.data, cert.size);
      o.site_cert_.size = cert.size;
    }
  } else if (message == 4) {
    ByteView result{};
    ByteView ignored{};
    status = join_ead_items_check(items, count, JoinEad::Result, false, result, ignored);
    if (status) {
      std::memcpy(o.result_.bytes.data(), result.data, result.size);
      o.result_.size = result.size;
    }
  }
  if (!status) ++o.stats_.ead_rejects;
  return status;
}

// === JoinHandshake ===========================================================

Status JoinHandshake::config_validate(const JoinHandshakeConfig& config,
                                      const IdentityRecord& identity) noexcept {
  if (config.node != identity.node_id) {
    return Status::error(StatusCode::InvalidArgument, "join node mismatch");
  }
  // Full structural check (pubkey/kid/keypair binding, anchors, DevCert).
  Status status = identity_validate(identity);
  if (!status) return status;
  switch (identity.key_location) {
    case CredentialKeyLocation::NvsPlaintext:
      break;  // the only executable location: the session takes the scalar
    case CredentialKeyLocation::None:
      return Status::error(StatusCode::InvalidState, "rli1 key location none");
    default:
      // External handles (eFuse/secure element): the session has only a
      // scalar API — refuse before sending; never treat the handle bytes
      // as the private scalar.
      return Status::error(StatusCode::Unsupported, "rli1 key handle");
  }
  if (config.org_hint == 0 || config.site_hint == 0 || config.network_low32 == 0) {
    return Status::error(StatusCode::InvalidArgument, "join hints");
  }
  if (config.requested_role == 0 || (config.requested_role & ~kMemberRoleMask) != 0 ||
      !role_executable(config.requested_role, config.capability)) {
    return Status::error(StatusCode::InvalidArgument, "join requested role");
  }
  if (config.last_site_id == 0) {
    if (config.last_generation != 0) {
      return Status::error(StatusCode::InvalidArgument, "join last generation");
    }
  } else if (!id_ok(config.last_site_id) || config.last_generation == 0) {
    return Status::error(StatusCode::InvalidArgument, "join last site");
  }
  CertClaims devcert{};
  status = cert_decode(identity.devcert.view(), devcert);
  if (!status) return status;
  devcert_model_ = devcert.model;
  return Status::success();
}

Status JoinHandshake::begin(const JoinHandshakeConfig& config, const IdentityRecord& identity,
                            EntropySource& entropy, const edhoc::AeadCcm* aead) noexcept {
  end();
  Status status = config_validate(config, identity);
  if (!status) return status;
  // Fresh nonzero C_I (4 B): a broken entropy source fails the attempt.
  cid_.fill(0);
  for (std::uint8_t i = 0; i < 4 && all_zero(cid_.data(), cid_.size()); ++i) {
    status = entropy.fill(MutableByteView{cid_.data(), cid_.size()});
    if (!status) return status;
  }
  if (all_zero(cid_.data(), cid_.size())) {
    return Status::error(StatusCode::InternalError, "join cid entropy");
  }
  identity_ = &identity;
  config_ = config;
  edhoc::SessionConfig session_config{};
  session_config.role = edhoc::Role::Initiator;
  session_config.method = edhoc::Method::SignatureSignature;
  session_config.connection_id = ByteView{cid_.data(), cid_.size()};
  session_config.credentials = &credentials_;
  session_config.ead = &ead_;
  session_config.random = &entropy_random;
  session_config.random_ctx = &entropy;
  session_config.aead = aead;
  status = session_.begin(session_config);
  if (!status) {
    identity_ = nullptr;
    return status;
  }
  stage_ = Stage::Begun;
  outcome_ = JoinAttemptOutcome::Pending;
  return Status::success();
}

Status JoinHandshake::compose_m1(MutableByteView out, std::size_t& length) noexcept {
  length = 0;
  if (stage_ != Stage::Begun) {
    return Status::error(StatusCode::InvalidState, "join m1 state");
  }
  const Status status = session_.compose_message_1(out, length);
  if (!status) return status;
  ++stats_.m1_composed;
  stage_ = Stage::M1Sent;
  return Status::success();
}

Status JoinHandshake::process_m2(const ByteView message) noexcept {
  if (stage_ != Stage::M1Sent) {
    return Status::error(StatusCode::InvalidState, "join m2 state");
  }
  Status status = session_.process_message_2(message);
  if (!status) {
    ++stats_.m2_failures;
    outcome_ = JoinAttemptOutcome::AuthenticationFailed;
    return status;
  }
  // Authenticated now: the offer must agree with the certified site AND
  // with the observed candidate hints (a hint collision is not identity).
  if (join_site_hint(offer_.site_id) != config_.site_hint ||
      offer_.network_low32 != config_.network_low32) {
    ++stats_.m2_failures;
    outcome_ = JoinAttemptOutcome::AuthenticationFailed;
    return Status::error(StatusCode::AuthenticationFailed, "join candidate binding");
  }
  status = site_offer_matches_site_cert(offer_, site_claims_);
  if (!status) {
    ++stats_.m2_failures;
    outcome_ = JoinAttemptOutcome::AuthenticationFailed;
    return status;
  }
  m2_ok_ = true;
  ++stats_.m2_authenticated;
  stage_ = Stage::M2Done;
  return Status::success();
}

Status JoinHandshake::compose_m3(MutableByteView out, std::size_t& length) noexcept {
  length = 0;
  if (stage_ != Stage::M2Done) {
    return Status::error(StatusCode::InvalidState, "join m3 state");
  }
  JoinRequest request{};
  request.model = devcert_model_;
  request.fw_version = config_.fw_version;
  request.capability = config_.capability;
  request.requested_role = config_.requested_role;
  request.last_site_id = config_.last_site_id;
  request.last_generation = config_.last_generation;
  Status status = join_request_encode(request, request_value_);
  if (!status) return status;
  status = session_.compose_message_3(out, length);
  if (!status) return status;
  ++stats_.m3_composed;
  stage_ = Stage::M3Sent;
  return Status::success();
}

Status JoinHandshake::process_m4(const ByteView message) noexcept {
  if (stage_ != Stage::M3Sent) {
    return Status::error(StatusCode::InvalidState, "join m4 state");
  }
  const Status status = session_.process_message_4(message);
  if (!status) {
    ++stats_.m4_failures;
    outcome_ = JoinAttemptOutcome::Failed;
    return status;
  }
  ++stats_.m4_authenticated;
  stage_ = Stage::M4Done;
  return Status::success();
}

Status JoinHandshake::decide(const JoinDecideInput& input, JoinDecided& out) noexcept {
  out = JoinDecided{};
  if (stage_ != Stage::M4Done) {
    return Status::error(StatusCode::InvalidState, "join decide state");
  }
  JoinResult result{};
  const Status decoded = join_result_decode(result_.view(), result);
  if (!decoded) {
    ++stats_.results_malformed;
    out.outcome = JoinAttemptOutcome::MalformedResult;
  } else {
    Status status = Status::success();
    switch (result.verdict) {
      case JoinVerdict::Allow:
        status = decide_allow(result, input, out);
        break;
      case JoinVerdict::PendingAssignment:
        out.outcome = JoinAttemptOutcome::PendingAssignment;
        out.retry_after_s = result.retry_after_s;
        break;
      case JoinVerdict::DenyNotHere:
        out.outcome = JoinAttemptOutcome::DenyNotHere;
        break;
      case JoinVerdict::DenyBlocked:
        out.outcome = JoinAttemptOutcome::DenyBlocked;
        break;
      case JoinVerdict::Removed:
        status = decide_removed(result, input, out);
        break;
      case JoinVerdict::AuthorityBusy:
        out.outcome = JoinAttemptOutcome::AuthorityBusy;
        out.retry_after_s = result.retry_after_s;
        break;
    }
    outcome_ = out.outcome;
    return status;
  }
  outcome_ = out.outcome;
  return Status::success();
}

Status JoinHandshake::decide_allow(const JoinResult& result, const JoinDecideInput& input,
                                   JoinDecided& out) noexcept {
  const bool strict = (identity_->flags & kIdentityFlagStrictAssignment) != 0;
  CertClaims member{};
  bool verified = false;
  const Status status = join_allow_verify(result, site_claims_, identity_->node_id,
                                          identity_->pubkey, strict, member, verified);
  if (!status || !verified) {
    ++stats_.allows_denied;
    out.outcome = JoinAttemptOutcome::MalformedResult;
    return Status::success();
  }
  // Local gates the authority cannot know (02 §10.2 rows 5-6): the granted
  // role must be executable on this hardware and the channel usable.
  if (!role_executable(member.role, config_.capability) ||
      !channel_usable(result.site_package.channel, config_.usable_channel_mask)) {
    ++stats_.allows_denied;
    out.outcome = JoinAttemptOutcome::MalformedResult;
    return Status::success();
  }
  return build_prepared(result, member, input, out);
}

Status JoinHandshake::decide_removed(const JoinResult& result, const JoinDecideInput& input,
                                     JoinDecided& out) noexcept {
  if (input.membership == nullptr) {
    ++stats_.removed_without_membership;
    out.outcome = JoinAttemptOutcome::RemovedNoMembership;
    return Status::success();
  }
  const JoinMembershipEvidence& evidence = *input.membership;
  bool verified = false;
  const Status status =
      removal_notice_verify(result.removal_notice, evidence.sak, evidence.site_id,
                            evidence.network, evidence.node, evidence.generation,
                            out.removal, verified);
  if (!status) {
    ++stats_.results_malformed;
    out.outcome = JoinAttemptOutcome::MalformedResult;
    return Status::success();
  }
  if (!verified) {
    ++stats_.notices_denied;
    out.outcome = JoinAttemptOutcome::RemovedDenied;
    return Status::success();
  }
  out.outcome = JoinAttemptOutcome::RemovedVerified;
  return Status::success();
}

Status JoinHandshake::build_prepared(const JoinResult& result, const CertClaims& member,
                                     const JoinDecideInput& input, JoinDecided& out) noexcept {
  SiteRecord& record = prepared_;
  record = SiteRecord{};
  record.state = SiteState::Member;
  record.site_id = site_claims_.subject;
  record.network = member.network;  // == site_package.network (verified)
  record.assignment_generation = member.assignment_generation;
  // A recovery join (the authenticated site is the held membership) keeps
  // the previously accepted floor; a new join starts at 0. The package's
  // rs_epoch is a fetch hint, never a floor.
  record.rs_epoch_floor =
      site_claims_.subject == config_.last_site_id ? input.prior_rs_epoch_floor : 0;
  record.gk_epoch_current = result.site_package.gk_epoch;
  record.gk_current = result.site_package.gk;
  record.role = member.role;
  record.gateway_count = result.site_package.gateway_count;
  record.gateways = result.site_package.gateways;
  record.channel = result.site_package.channel;
  record.channel_epoch = result.site_package.channel_epoch;
  record.boot_witness = input.boot_witness;
  record.site_cert = site_cert_;
  if (result.member_cert.size > record.member_cert.bytes.size()) {
    return Status::error(StatusCode::InternalError, "member cert slot");
  }
  std::memcpy(record.member_cert.bytes.data(), result.member_cert.data, result.member_cert.size);
  record.member_cert.size = result.member_cert.size;
  // DAMS: only after m4 key confirmation and the whole Allow matrix. The
  // context uses authenticated values only; a zero output is impossible.
  ByteBuffer<kJoinDamsContextMax> context{};
  Status status = dams_exporter_context(member.network, identity_->node_id,
                                        site_claims_.subject, identity_->kid, sak_kid_, context);
  if (!status) return status;
  status = session_.exporter(keys::kExporterDams, context.view(),
                             MutableByteView{record.dams.data(), record.dams.size()});
  if (!status) return status;
  secure_clear(context.bytes.data(), context.bytes.size());
  if (all_zero(record.dams.data(), record.dams.size())) {
    return Status::error(StatusCode::InternalError, "dams zero");
  }
  // Invariant self-check: the record we just built must pass the same
  // structural and binding gates a stored one would.
  status = site_validate(record);
  if (status) status = site_matches_identity(record, *identity_);
  if (!status) {
    secure_clear(record.dams.data(), record.dams.size());
    return Status::error(StatusCode::InternalError, "prepared self-check");
  }
  out.rs_epoch_to_fetch = result.site_package.rs_epoch;
  out.record = &prepared_;
  out.outcome = JoinAttemptOutcome::AllowVerified;
  return Status::success();
}

void JoinHandshake::end() noexcept {
  session_.end();
  secure_clear(site_cert_.bytes.data(), site_cert_.bytes.size());
  secure_clear(result_.bytes.data(), result_.bytes.size());
  secure_clear(prepared_.dams.data(), prepared_.dams.size());
  secure_clear(intent_value_.bytes.data(), intent_value_.bytes.size());
  secure_clear(request_value_.bytes.data(), request_value_.bytes.size());
  prepared_ = SiteRecord{};
  site_cert_ = ByteBuffer<kRlcw1CertMax>{};
  result_ = ByteBuffer<kJoinResultMax>{};
  site_claims_ = CertClaims{};
  offer_ = SiteOffer{};
  sak_kid_ = Digest256{};
  cid_.fill(0);
  devcert_model_ = 0;
  identity_ = nullptr;
  config_ = JoinHandshakeConfig{};
  stage_ = Stage::Idle;
  m2_ok_ = false;
  outcome_ = JoinAttemptOutcome::Pending;
}

}  // namespace routeloom::sdkv1
