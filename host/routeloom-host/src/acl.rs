//! Principal/permission gate for the API1 IPC surface.
//!
//! The principal is derived *only* from the socket peer's OS credential
//! (see `routeloom_peercred`) — never from request JSON, process names, or
//! anything else the client can write. What a uid may do comes from a
//! daemon-configured ACL file (`--api-acl-file`):
//!
//! ```json
//! {
//!   "principals": {
//!     "501": {
//!       "networks": {
//!         "*":                    ["READ_OPERATION"],
//!         "0000000000000001":     ["READ_PAYLOAD", "SEND"]
//!       }
//!     },
//!     "0": { "networks": { "*": ["READ_PAYLOAD", "SEND", "READ_OPERATION"] } }
//!   }
//! }
//! ```
//!
//! - Top level: a single required object `principals`; unknown fields are
//!   rejected (strict load — a misspelled key must not silently deny or
//!   silently grant).
//! - `principals` maps a *decimal* uid string to `{ "networks": {...} }`.
//! - `networks` maps a 16-hex network id — or `"*"` for all networks — to a
//!   non-empty array of permission names.
//! - Permission names: `READ_PAYLOAD`, `SEND`, `READ_OPERATION`. Unknown
//!   names are rejected at load time.
//!
//! Semantics: default deny. A uid with no entry, a network with no grant
//! (including no `"*"`), or a permission not listed all fail authorization.
//! Diagnostics verbs on the same socket (STATUS/EVENTS/…) do not consult
//! this ACL — they are the pre-existing unauthenticated diagnostic surface.
//!
//! The file is loaded once at daemon start; there is no reload yet. Each
//! load bumps `revision`, which is embedded in read cursors so a future
//! reload invalidates outstanding cursor views (CURSOR_SCOPE_MISMATCH)
//! instead of silently re-scoping them.

use routeloom_json::Json;
use std::collections::HashMap;
use std::path::Path;

pub const PERM_READ_PAYLOAD: u8 = 1;
pub const PERM_SEND: u8 = 2;
pub const PERM_READ_OPERATION: u8 = 4;

/// Depth bound for the ACL document itself (same strict parser as IPC).
const ACL_MAX_DEPTH: usize = 8;

#[derive(Debug, Default)]
pub struct Acl {
    /// View revision: 0 = no ACL configured, otherwise load counter.
    revision: u64,
    /// (uid, network pattern) -> permission bits.
    grants: HashMap<u32, Vec<(Option<u64>, u8)>>,
}

impl Acl {
    /// No ACL configured: every privileged method is denied for every uid.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// `network` is the concrete network being accessed; `None` grants in
    /// the file mean "any network".
    pub fn permit(&self, uid: u32, network: u64, permission: u8) -> bool {
        self.grants.get(&uid).is_some_and(|grants| {
            grants.iter().any(|(pattern, bits)| {
                bits & permission != 0 && pattern.map_or(true, |n| n == network)
            })
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read ACL file {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let root = routeloom_json::parse_bounded(text, ACL_MAX_DEPTH)
            .map_err(|e| format!("ACL file is not valid JSON: {e}"))?;
        if !matches!(root, Json::Object(_)) {
            return Err("ACL: top level must be an object".to_string());
        }
        let mut acl = Acl {
            revision: 1,
            grants: HashMap::new(),
        };
        let mut saw_principals = false;
        for (key, value) in root.object_entries() {
            if key != "principals" {
                return Err(format!("ACL: unknown top-level field \"{key}\""));
            }
            saw_principals = true;
            let Json::Object(principals) = value else {
                return Err("ACL: \"principals\" must be an object".to_string());
            };
            for (uid_key, principal) in principals {
                let uid: u32 = uid_key.parse().map_err(|_| {
                    format!("ACL: principal key \"{uid_key}\" is not a decimal uid")
                })?;
                // Non-canonical spellings ("+501", "0501") parse to the
                // same uid yet are distinct JSON keys — grants would merge
                // silently. Only the canonical decimal form may name a
                // principal.
                if uid_key.as_str() != uid.to_string() {
                    return Err(format!(
                        "ACL: principal key \"{uid_key}\" is not canonical decimal"
                    ));
                }
                let grants = acl.grants.entry(uid).or_default();
                let Json::Object(fields) = principal else {
                    return Err(format!("ACL: principal \"{uid_key}\" must be an object"));
                };
                for (field, networks) in fields {
                    if field != "networks" {
                        return Err(format!(
                            "ACL: unknown field \"{field}\" for principal \"{uid_key}\""
                        ));
                    }
                    let Json::Object(networks) = networks else {
                        return Err(format!(
                            "ACL: \"networks\" for principal \"{uid_key}\" must be an object"
                        ));
                    };
                    for (network_key, permissions) in networks {
                        let network = if network_key == "*" {
                            None
                        } else {
                            Some(
                                parse_network_hex(network_key)
                                    .map_err(|e| format!("ACL: network \"{network_key}\": {e}"))?,
                            )
                        };
                        let bits = parse_permissions(permissions).map_err(|e| {
                            format!("ACL: principal \"{uid_key}\" network \"{network_key}\": {e}")
                        })?;
                        grants.push((network, bits));
                    }
                }
            }
        }
        if !saw_principals {
            return Err("ACL: missing \"principals\"".to_string());
        }
        Ok(acl)
    }
}

/// Parse one permission array into bits. Unknown names reject the file.
fn parse_permissions(value: &Json) -> Result<u8, String> {
    let Json::Array(items) = value else {
        return Err("permissions must be an array".to_string());
    };
    if items.is_empty() {
        return Err("permissions array is empty".to_string());
    }
    let mut bits = 0_u8;
    for item in items {
        bits |= match item.as_str() {
            Some("READ_PAYLOAD") => PERM_READ_PAYLOAD,
            Some("SEND") => PERM_SEND,
            Some("READ_OPERATION") => PERM_READ_OPERATION,
            Some(other) => return Err(format!("unknown permission \"{other}\"")),
            None => return Err("permission entries must be strings".to_string()),
        };
    }
    Ok(bits)
}

/// 16-hex network id, normalized to lowercase before parsing (IPC contract).
/// Wire v1 networks are `1..=0xffffffff` — outside that range the id can
/// never appear on the wire, so it is rejected rather than stored.
pub fn parse_network_hex(text: &str) -> Result<u64, String> {
    let normalized = text.to_ascii_lowercase();
    if normalized.len() != 16 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("\"{text}\" is not a 16-hex id"));
    }
    let value = u64::from_str_radix(&normalized, 16).map_err(|_| "invalid hex".to_string())?;
    if !(1..=0xffff_ffff).contains(&value) {
        return Err(format!("\"{text}\" is outside the wire-v1 network range"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{
        "principals": {
            "501": {"networks": {
                "*": ["READ_OPERATION"],
                "0000000000000001": ["READ_PAYLOAD", "SEND"]
            }},
            "7": {"networks": {"0000000000000002": ["READ_PAYLOAD"]}}
        }
    }"#;

    #[test]
    fn loads_and_permits() {
        let acl = Acl::parse(DOC).unwrap();
        assert_eq!(acl.revision(), 1);
        assert!(acl.permit(501, 1, PERM_READ_PAYLOAD));
        assert!(acl.permit(501, 1, PERM_SEND));
        assert!(acl.permit(501, 9, PERM_READ_OPERATION)); // "*" grant
        assert!(!acl.permit(501, 9, PERM_READ_PAYLOAD));
        assert!(acl.permit(7, 2, PERM_READ_PAYLOAD));
        assert!(!acl.permit(7, 1, PERM_READ_PAYLOAD));
    }

    #[test]
    fn default_denies_everything() {
        let acl = Acl::empty();
        assert_eq!(acl.revision(), 0);
        assert!(!acl.permit(0, 1, PERM_READ_PAYLOAD));
        assert!(!acl.permit(501, 1, PERM_READ_PAYLOAD));
    }

    #[test]
    fn rejects_bad_documents() {
        for doc in [
            "{}",
            "{\"principals\":[]}",
            "{\"principals\":{\"x\":{\"networks\":{\"*\":[\"READ_PAYLOAD\"]}}}}",
            "{\"principals\":{\"1\":{\"networks\":{\"*\":[\"ROOT\"]}}}}",
            "{\"principals\":{\"1\":{\"networks\":{\"zz00000000000000\":[\"SEND\"]}}}}",
            "{\"principals\":{\"1\":{\"networks\":{\"*\":[]}}}}",
            "{\"principals\":{\"1\":{\"networks\":{\"*\":[\"SEND\"]}},\"bogus\":1}}",
            "{\"principals\":{\"1\":{\"networks\":{\"*\":[\"SEND\"],\"*\":[\"SEND\"]}}}}",
        ] {
            assert!(Acl::parse(doc).is_err(), "should reject: {doc}");
        }
    }

    #[test]
    fn principal_keys_must_be_canonical_decimal() {
        // "+501"/"0501" parse to 501 but are distinct JSON keys — merging
        // them into the same principal would silently combine grants.
        for key in ["+501", "0501", " 501", "501 "] {
            let doc =
                format!("{{\"principals\":{{\"{key}\":{{\"networks\":{{\"*\":[\"SEND\"]}}}}}}}}");
            assert!(Acl::parse(&doc).is_err(), "should reject: {key}");
        }
        // The canonical spelling still loads.
        let doc = "{\"principals\":{\"501\":{\"networks\":{\"*\":[\"SEND\"]}}}}";
        assert!(Acl::parse(doc).unwrap().permit(501, 9, PERM_SEND));
    }

    #[test]
    fn network_hex_normalizes_and_ranges() {
        assert_eq!(parse_network_hex("00000000000000AB").unwrap(), 0xAB);
        assert_eq!(parse_network_hex("00000000FFFFFFFF").unwrap(), 0xffff_ffff);
        assert!(parse_network_hex("0000000100000000").is_err()); // > wire v1 range
        assert!(parse_network_hex("0000000000000000").is_err());
        assert!(parse_network_hex("1").is_err());
        assert!(parse_network_hex("00000000000000gg").is_err());
    }
}
