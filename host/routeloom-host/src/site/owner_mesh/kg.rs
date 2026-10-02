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

fn submit(
    world: &MeshWorld,
    epoch: &str,
    key: u64,
    dest: u64,
    payload: &[u8],
    latest: bool,
) -> Json {
    let (delivery, queue) = if latest {
        ("BEST_EFFORT", "LATEST_PER_DESTINATION")
    } else {
        ("RELIABLE", "FIFO")
    };
    daemon(world).api(
        "messages.submit",
        &format!(
            r#"{{"network":"{:016x}","admission_epoch":"{epoch}","key":"{key:032x}","destination":{{"kind":"node","id":"{dest:016x}"}},"payload_hex":"{}","payload_len":{},"options":{{"storage":"RAM_ONLY","delivery":"{delivery}","queue_mode":"{queue}","ttl_ms":5000}}}}"#,
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
            .map(|n| {
                (
                    if nodes == 5 && n == 2 {
                        1
                    } else if n < 3 {
                        0
                    } else {
                        1 + n % 2
                    },
                    n,
                )
            })
            .collect(),
    };
    let mut world =
        MeshWorld::start_plan(tag, Switch::new(&topology), &staggered_boot(nodes), false)?;
    for gated in 2..nodes {
        world.gate[gated] = true;
    }
    for ready in 2..=nodes {
        world.pump_until(2400, |snaps| {
            snaps[..ready]
                .iter()
                .all(|s| s.authority_ready && s.join_confirmed)
        });
        assert!(
            world.snaps[..ready]
                .iter()
                .all(|s| s.authority_ready && s.join_confirmed),
            "staged load world {tag}, ready {ready}"
        );
        if ready < nodes {
            world.gate[ready] = false;
        }
    }
    converge(&mut world, tag);
    world.usb_host.daemon = Some(daemon::MeshDaemon::new(world.now));
    world.pump_until(80, |_| false);
    Some(world)
}

#[test]
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
    let mut content_received = 0;
    let mut last_view = [world.now; 5];
    let mut last_rx = [0; 5];
    for slot in 0..60_u64 {
        if slot == 12 {
            world.switch.set_noise(
                LegNoise {
                    loss_ppm: 10_000,
                    ..LegNoise::default()
                },
                21,
            );
        }
        let mut view = [0_u8; 10];
        view[..8].copy_from_slice(&slot.to_be_bytes());
        if slot % 12 == 0 {
            for index in [3, 4] {
                key += 1;
                let mut content = [0_u8; 127];
                content[..8].copy_from_slice(&slot.to_be_bytes());
                result(&submit(
                    &world,
                    &epoch,
                    key,
                    world.nodes[index],
                    &content,
                    false,
                ));
            }
        }
        for index in [3, 4] {
            key += 1;
            let response = submit(&world, &epoch, key, world.nodes[index], &view, true);
            result(&response);
        }
        if slot % 3 == 0 || slot % 18 == 1 {
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
            for index in [3, 4] {
                let snap = &world.snaps[index];
                if snap.rx_count != last_rx[index] && snap.rx.len() == 10 {
                    last_view[index] = world.now;
                }
                last_rx[index] = snap.rx_count;
                assert!(
                    world.now - last_view[index] < 20_000,
                    "continuous view freshness"
                );
            }
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
            let received = world.peers[index].receipts();
            content_received += received.iter().filter(|r| r.3.len() == 127).count();
            if slot < 12 {
                assert!(
                    received.iter().any(|r| r.3 == view),
                    "latest value in its normal 5 s slot"
                );
            }
        }
    }
    assert_eq!(content_received, 10, "127 B content every 60 s");
    assert_eq!(
        seen.len(),
        expected,
        "all reliable status and change events retained"
    );
    assert!(world.switch.noise_hits.lost > 0, "leg noise fired");
    assert!(world
        .snaps
        .iter()
        .all(|s| s.mode == MODE_MEMBER && s.phase == PHASE_ACTIVE));
    latency.sort_unstable();
    let p99 = latency[(99 * latency.len()).div_ceil(100) - 1];
    assert!(p99 < 2_000, "status p99 {p99} ms");
    eprintln!("K01: {expected}/{expected} status/events, p99 {p99} ms, CURSOR_GAP 0");
}

#[test]
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
fn mesh_k03_simultaneous_latest_and_group() {
    let nodes = if max_nodes() == 32 { 32 } else { 6 };
    let Some(mut world) = load_world("k03", nodes) else {
        return;
    };
    let full = nodes - 1;
    let epoch = open_epoch(&world);
    let before: Vec<_> = world.snaps.iter().map(|s| s.group_delivered).collect();
    world.peers[0].group_send(0xFFFF, b"all-disabled");
    let start = world.now;
    let mut accepted = 0;
    let mut refused = 0;
    for index in 1..nodes {
        if index == full {
            world.pump_until(200, |snaps| {
                snaps
                    .iter()
                    .enumerate()
                    .skip(1)
                    .take(nodes - 2)
                    .all(|(i, s)| s.rx == b"latest" && s.group_delivered == before[i] + 1)
            });
            assert!(world.peers[0]
                .tracked_burst(8, u64::MAX - 1)
                .iter()
                .all(|r| r.0 == 0));
        }
        let response = submit(
            &world,
            &epoch,
            index as u64,
            world.nodes[index],
            b"latest",
            true,
        );
        if response.get("ok").and_then(Json::as_bool) == Some(true) {
            accepted += 1;
            if index == 1 {
                let retry = submit(
                    &world,
                    &epoch,
                    index as u64,
                    world.nodes[index],
                    b"latest",
                    true,
                );
                assert_eq!(
                    result(&response).get("operation_id"),
                    result(&retry).get("operation_id"),
                    "lost admission response reuses the operation"
                );
            }
            world.peers[index].app_send(testkit::GATEWAY, b"parallel-status");
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
    assert_eq!(
        accepted - 1,
        delivered,
        "one full destination, others delivered"
    );
    let outcome = daemon(&world).api(
        "operations.get_by_key",
        &format!(
            r#"{{"network":"{:016x}","admission_epoch":"{epoch}","key":"{full:032x}"}}"#,
            network(&world)
        ),
        world.now,
    );
    assert_ne!(
        result(&outcome).get("device_outcome"),
        Some(&Json::Null),
        "full destination has an explicit device outcome: {outcome:?}"
    );
    assert_eq!(accepted + refused, nodes - 1);
}

#[test]
fn mesh_g7_authenticated_receive_reaches_daemon_store() {
    let fixture = daemon::MeshDaemon::new(0);
    let mut limiter = fixture.state.rate_limiter.lock().unwrap();
    let principal = routeloom_peercred::Principal::UnixUid(501);
    let destination = Some((1, 0, NODE_A));
    for _ in 0..4 {
        assert!(limiter.admit_submit(&principal, destination, 0).is_ok());
    }
    assert_eq!(
        limiter
            .admit_submit(&principal, destination, 0)
            .unwrap_err()
            .scope,
        "destination",
        "latest-value burst is bounded per destination"
    );
    assert!(limiter.admit_submit(&principal, destination, 5_000).is_ok());
    drop(limiter);
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
    let records = result(&response)
        .get("records")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("payload_hex").unwrap().as_str(),
        Some(hex(b"authenticated-status").as_str())
    );
}
