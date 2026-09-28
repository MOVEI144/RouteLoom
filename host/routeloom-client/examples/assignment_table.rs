//! Minimal external decider for the zero-touch join (docs/spec/host.md §11):
//! an assignment table and the rule "assigned here → allow, assigned
//! elsewhere → deny not_here, blocked → deny blocked, unknown → pending"
//! (docs/design/sdk-v1/07 §5). A key conflict is never allowed
//! automatically.
//!
//! `cargo run -p routeloom-client --example assignment_table -- <socket>
//! <network-low32-hex> [<node-hex>=endpoint|relay|gateway|elsewhere|blocked ...]`

use std::collections::HashMap;
use std::sync::Mutex;

use routeloom_client::site::{Decision, DecisionOutcome, JoinRequest, Role, SiteAdmin};
use routeloom_client::{NodeId, TransportError};

/// Where the table puts a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assignment {
    Here(Role),
    Elsewhere,
    Blocked,
}

pub struct AssignmentTable {
    assignments: Mutex<HashMap<NodeId, Assignment>>,
    pub pending_retry_s: u32,
}

impl Default for AssignmentTable {
    fn default() -> Self {
        Self {
            assignments: Mutex::new(HashMap::new()),
            pending_retry_s: 60,
        }
    }
}

impl AssignmentTable {
    pub fn assign(&self, device: NodeId, assignment: Assignment) {
        self.assignments
            .lock()
            .expect("assignments poisoned")
            .insert(device, assignment);
    }

    pub fn decision_for(&self, request: &JoinRequest) -> Decision {
        if request.kid_conflict {
            return Decision::Pending {
                retry_after_s: self.pending_retry_s,
            };
        }
        match self
            .assignments
            .lock()
            .expect("assignments poisoned")
            .get(&request.device)
        {
            Some(Assignment::Here(role)) => Decision::Allow(*role),
            Some(Assignment::Elsewhere) => Decision::DenyNotHere,
            Some(Assignment::Blocked) => Decision::DenyBlocked,
            None => Decision::Pending {
                retry_after_s: self.pending_retry_s,
            },
        }
    }

    /// Decides every open, undecided request once. Returns what it did.
    pub fn serve_once(
        &self,
        admin: &dyn SiteAdmin,
    ) -> Result<Vec<(JoinRequest, Decision, DecisionOutcome)>, TransportError> {
        let mut done = Vec::new();
        for request in admin.join_requests()? {
            if request.decided {
                continue;
            }
            let decision = self.decision_for(&request);
            let key = format!("table-{}-{}", request.id, request.attempt);
            let outcome = admin.decide(&request, decision, &key)?;
            done.push((request, decision, outcome));
        }
        Ok(done)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [socket, network, assignments @ ..] = args.as_slice() else {
        return Err(
            "usage: assignment_table <socket> <network-low32-hex> [<node-hex>=<assignment> ...]"
                .into(),
        );
    };
    let site =
        routeloom_client::api1::RouteLoomTransport::new(socket, u64::from_str_radix(network, 16)?);
    let table = AssignmentTable::default();
    for entry in assignments {
        let (node, role) = entry
            .split_once('=')
            .ok_or("expected <node-hex>=<assignment>")?;
        let assignment = match role {
            "endpoint" => Assignment::Here(Role::Endpoint),
            "relay" => Assignment::Here(Role::Relay),
            "gateway" => Assignment::Here(Role::Gateway),
            "elsewhere" => Assignment::Elsewhere,
            "blocked" => Assignment::Blocked,
            _ => return Err(format!("unknown assignment {role}").into()),
        };
        table.assign(u64::from_str_radix(node, 16)?, assignment);
    }
    // Subscribe before draining existing requests so a join arriving during
    // startup is covered by either the snapshot or the event stream.
    let events = site.site_events()?;
    for (request, decision, _) in table.serve_once(&site)? {
        println!("{:016x}: {decision:?}", request.device);
    }
    for event in events {
        if event?.kind == "join.request" {
            for (request, decision, _) in table.serve_once(&site)? {
                println!("{:016x}: {decision:?}", request.device);
            }
        }
    }
    Ok(())
}
