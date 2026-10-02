//! Periodic latest values, reliable status and change events through real peers.

use super::*;
use routeloom_json::Json;

fn daemon(world: &MeshWorld) -> &daemon::MeshDaemon {
    world.usb_host.daemon.as_ref().unwrap()
}

fn result(response: &Json) -> &Json {
    assert_eq!(
        response.get("ok").and_then(Json::as_bool),
        Some(true),
        "{response:?}"
    );
    response.get("result").unwrap()
}

fn network(world: &MeshWorld) -> u64 {
    world.usb_host.hello_network.unwrap()
}

fn open_epoch(world: &MeshWorld) -> String {
    let response = daemon(world).api(
        "operations.open_epoch",
        &format!(r#"{{"network":"{:016x}"}}"#, network(world)),
        world.now,
    );
    result(&response)
        .get("admission_epoch")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn submit(world: &MeshWorld, epoch: &str, key: u64, dest: u64, payload: &[u8]) -> Json {
    daemon(world).api(
        "messages.submit",
        &format!(
            r#"{{"network":"{:016x}","admission_epoch":"{epoch}","key":"{key:032x}","destination":{{"kind":"node","id":"{dest:016x}"}},"payload_hex":"{}","payload_len":{},"options":{{"storage":"RAM_ONLY","delivery":"BEST_EFFORT","queue_mode":"LATEST_PER_DESTINATION","ttl_ms":5000}}}}"#,
            network(world), hex(payload), payload.len(),
        ),
        world.now,
    )
}

fn read(world: &MeshWorld, cursor: Option<&str>) -> Json {
    let position = cursor.map_or(r#""from":"earliest""#.to_string(), |c| {
        format!(r#""cursor":"{c}""#)
    });
    daemon(world).api(
        "messages.read",
        &format!(r#"{{"network":"{:016x}",{position}}}"#, network(world)),
        world.now,
    )
}

fn load_world(tag: &str, nodes: usize) -> Option<MeshWorld> {
    let topology = Topology {
        nodes,
        edges: (1..nodes)
            .map(|n| (if n < 3 { 0 } else { 1 + n % 2 }, n))
            .collect(),
    };
    let mut world =
        MeshWorld::start_plan(tag, Switch::new(&topology), &staggered_boot(nodes), false)?;
    converge(&mut world, tag);
    world.usb_host.daemon = Some(daemon::MeshDaemon::new(world.now));
    world.pump_until(80, |_| false);
    Some(world)
}

#[test]
#[ignore = "#195/#127: API1 rejects the authenticated epoch-qualified network"]
fn mesh_k01_periodic_latest_status_and_events() {
    let Some(mut world) = load_world("k01", 5) else {
        return;
    };
    let epoch = open_epoch(&world);
    let start = world.now;
    let mut key = 100;
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut latency = Vec::new();
    let mut expected = 0;
    for slot in 0..60_u64 {
        let mut view = [0_u8; 10];
        view[..8].copy_from_slice(&slot.to_be_bytes());
        for index in [3, 4] {
            key += 1;
            let response = submit(&world, &epoch, key, world.nodes[index], &view);
            result(&response);
        }
        if slot % 3 == 0 || slot % 9 == 1 {
            for index in [3, 4] {
                let mut status = [0_u8; 34];
                status[..8].copy_from_slice(&world.now.to_be_bytes());
                status[8..16].copy_from_slice(&key.to_be_bytes());
                status[16] = index as u8;
                world.peers[index].app_send(testkit::GATEWAY, &status);
                expected += 1;
            }
        }
        let until = start + (slot + 1) * 5_000;
        while world.now < until {
            world.step(25);
            if world.now % 1000 < 25 {
                let response = read(&world, cursor.as_deref());
                let page = result(&response);
                for record in page.get("records").unwrap().as_array().unwrap() {
                    let payload = record.get("payload_hex").unwrap().as_str().unwrap();
                    assert!(
                        seen.insert(payload.to_string()),
                        "one consumer persistence per event"
                    );
                    let sent = u64::from_str_radix(&payload[..16], 16).unwrap();
                    latency.push(world.now - sent);
                }
                cursor = Some(
                    page.get("next_cursor")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
            }
        }
        for index in [3, 4] {
            assert_eq!(world.snaps[index].rx, view, "latest value in its 5 s slot");
        }
    }
    assert_eq!(
        seen.len(),
        expected,
        "all reliable status and change events retained"
    );
    latency.sort_unstable();
    let p99 = latency[(99 * latency.len()).div_ceil(100) - 1];
    assert!(p99 < 2_000, "status p99 {p99} ms");
    eprintln!("K01: {expected}/{expected} status/events, p99 {p99} ms, CURSOR_GAP 0");
}

#[test]
#[ignore = "#195/#127: API1 rejects the authenticated epoch-qualified network"]
fn mesh_k05_cursor_replay_gap_and_epoch_change() {
    let Some(mut world) = load_world("k05", 3) else {
        return;
    };
    let first = read(&world, None);
    let cursor = result(&first)
        .get("next_cursor")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    world.peers[1].app_send(testkit::GATEWAY, b"cursor-message");
    world.pump_until(400, |_| false);
    let page = read(&world, Some(&cursor));
    assert_eq!(
        result(&page)
            .get("records")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let retry = read(&world, Some(&cursor));
    assert_eq!(
        format!("{page:?}"),
        format!("{retry:?}"),
        "crash before persistence re-reads same page"
    );
    world.pump_until(2400, |_| false);
    result(&read(&world, Some(&cursor)));
    world.pump_until(12_100, |_| false);
    let gap = read(&world, Some(&cursor));
    assert_eq!(
        gap.get("error").unwrap().get("code").unwrap().as_str(),
        Some("CURSOR_GAP")
    );
    world.usb_host.daemon = Some(daemon::MeshDaemon::new(world.now));
    let changed = read(&world, Some(&cursor));
    assert_eq!(
        changed.get("error").unwrap().get("code").unwrap().as_str(),
        Some("CURSOR_EPOCH_CHANGED")
    );
}

#[test]
#[ignore = "#195/#127: API1 rejects the authenticated epoch-qualified network"]
fn mesh_k03_simultaneous_latest_and_group() {
    let nodes = if max_nodes() == 32 { 32 } else { 6 };
    let Some(mut world) = load_world("k03", nodes) else {
        return;
    };
    let epoch = open_epoch(&world);
    let before: Vec<_> = world.snaps.iter().map(|s| s.group_delivered).collect();
    world.peers[0].group_send(1, b"all-disabled");
    let start = world.now;
    let mut accepted = 0;
    let mut refused = 0;
    for index in 1..nodes {
        let response = submit(&world, &epoch, index as u64, world.nodes[index], b"latest");
        if response.get("ok").and_then(Json::as_bool) == Some(true) {
            accepted += 1;
        } else {
            let error = response.get("error").unwrap();
            assert!(
                matches!(
                    error.get("code").unwrap().as_str(),
                    Some("RATE_LIMITED" | "NO_CAPACITY")
                ),
                "{error:?}"
            );
            assert!(
                error.get("retryable").is_none()
                    || error.get("retryable").and_then(Json::as_bool) == Some(true)
            );
            refused += 1;
        }
    }
    world.pump_until(200, |snaps| {
        snaps
            .iter()
            .enumerate()
            .skip(1)
            .all(|(i, s)| s.group_delivered == before[i] + 1)
    });
    assert!(world.now - start <= 5000);
    for (index, count) in before.iter().enumerate().skip(1) {
        assert_eq!(
            world.snaps[index].group_delivered,
            count + 1,
            "group delivered once"
        );
    }
    world.pump_until(1000, |_| false);
    let delivered = world
        .snaps
        .iter()
        .skip(1)
        .filter(|s| s.rx == b"latest")
        .count();
    assert_eq!(accepted, delivered);
    assert_eq!(accepted + refused, nodes - 1);
}

#[test]
fn mesh_g7_authenticated_receive_reaches_daemon_store() {
    let Some(mut world) = load_world("g7-receive", 3) else {
        return;
    };
    world.peers[1].app_send(testkit::GATEWAY, b"authenticated-status");
    world.pump_until(400, |_| false);
    let network = network(&world);
    let mut log = daemon(&world).state.receive_log.lock().unwrap();
    let crate::receive_log::ReadOutcome::Batch(batch) = log.read(network, 0, 10, world.now, false)
    else {
        panic!("fresh receive log");
    };
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].payload, b"authenticated-status");
    assert_eq!(batch.records[0].origin, NODE_A);
    drop(log);
    let response = read(&world, None);
    assert_eq!(
        response.get("error").unwrap().get("code").unwrap().as_str(),
        Some("INVALID_ARGUMENT"),
        "epoch-qualified network rejection is an explicit pending acceptance"
    );
}
