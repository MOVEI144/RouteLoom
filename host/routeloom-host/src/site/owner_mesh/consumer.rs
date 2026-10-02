//! P06/K05/K01: the documented consumer reads the production API1 socket
//! after real Owners deliver verified DataFromMesh through HostLink.

use super::*;
use routeloom_json::Json;
use rusqlite::Connection;

struct ConsumerEndpoint {
    state: Arc<State>,
    socket: std::path::PathBuf,
    stop: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
}

impl ConsumerEndpoint {
    fn start(dir: &std::path::Path, network: u64) -> Self {
        let uid = std::fs::metadata(dir).unwrap().uid();
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"{network:016x}\":[\"READ_PAYLOAD\"]}}}}}}}}"
        ))
        .unwrap();
        let state = Arc::new(State {
            acl,
            receive_log: Mutex::new(crate::receive_log::ReceiveLog::new(crate::mint_id128())),
            ..State::default()
        });
        let socket = dir.join("consumer.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_state = Arc::clone(&state);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let principal = routeloom_peercred::peer_uid(&stream)
                    .ok()
                    .map(routeloom_peercred::Principal::UnixUid);
                let state = Arc::clone(&thread_state);
                thread::spawn(move || {
                    let (outbound, _receiver) = mpsc::sync_channel(64);
                    serve_client(
                        routeloom_peercred::IpcStream::from_unix(stream),
                        state,
                        outbound,
                        0,
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(Mutex::new(DeviceSession::new())),
                        principal,
                    )
                    .expect("production API1 serves consumer");
                });
            }
        });
        Self {
            state,
            socket,
            stop,
            listener: Some(handle),
        }
    }

    fn read(&self, network: u64, cursor: Option<&str>) -> Json {
        use std::io::{BufRead, BufReader};
        let position = cursor.map_or_else(
            || "\"from\":\"earliest\"".to_string(),
            |c| format!("\"cursor\":\"{c}\""),
        );
        let mut conn = UnixStream::connect(&self.socket).unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        writeln!(conn, "API1 {{\"v\":1,\"request_id\":\"consumer-read\",\"method\":\"messages.read\",\"params\":{{\"network\":\"{network:016x}\",{position},\"limit\":32}}}}") .unwrap();
        let mut line = String::new();
        BufReader::new(conn).read_line(&mut line).unwrap();
        routeloom_json::parse(line.trim()).unwrap()
    }

    fn run_example(
        &self,
        network: u64,
        db: &std::path::Path,
        resume: Option<&str>,
    ) -> std::process::Output {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/display_consumer/consumer.py");
        let mut command = Command::new("python3");
        command
            .arg(script)
            .arg("--socket")
            .arg(&self.socket)
            .arg("--network")
            .arg(format!("{network:016x}"))
            .arg("--db")
            .arg(db)
            .arg("--once");
        if let Some(cursor) = resume {
            command.arg("--resume-cursor").arg(cursor);
        }
        command.output().expect("documented Python consumer")
    }
}

impl Drop for ConsumerEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket);
        self.listener.take().unwrap().join().unwrap();
        std::fs::remove_file(&self.socket).unwrap();
    }
}

fn next_cursor(reply: &Json) -> String {
    assert_eq!(
        reply.get("ok").and_then(Json::as_bool),
        Some(true),
        "{reply:?}"
    );
    reply
        .get("result")
        .unwrap()
        .get("next_cursor")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn records(reply: &Json) -> usize {
    reply
        .get("result")
        .unwrap()
        .get("records")
        .unwrap()
        .as_array()
        .unwrap()
        .len()
}

fn error(reply: &Json) -> &str {
    assert_eq!(reply.get("ok").and_then(Json::as_bool), Some(false));
    reply
        .get("error")
        .unwrap()
        .get("code")
        .unwrap()
        .as_str()
        .unwrap()
}

fn db_position(db: &std::path::Path) -> (usize, String) {
    let conn = Connection::open(db).unwrap();
    let count = conn
        .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .unwrap();
    let cursor = conn
        .query_row("SELECT cursor FROM cursors", [], |r| r.get(0))
        .unwrap();
    (count, cursor)
}

fn devram_world(tag: &str, switch: Switch) -> MeshWorld {
    let mut world = MeshWorld::start_with_args(tag, switch, &["--devram"], &["--devram"])
        .expect("documented smoke requires real Owner peers");
    world.pump_until(4000, |snaps| {
        snaps.iter().all(|s| s.mode == 3 && s.link_sessions > 0)
    });
    assert!(world
        .snaps
        .iter()
        .all(|s| s.mode == 3 && s.link_sessions > 0));
    world.pump_until(400, |_| false);
    world
}

/// The receive log attributes a Member record to the authenticated full
/// network; the current API1 parser rejects its high word before reading it.
#[test]
#[ignore = "Member full network is rejected by API1; tracked as K05-M in scenarios.json"]
fn mesh_k05_member_full_network_consumer() {
    let mut world =
        MeshWorld::start("k05-member", Switch::direct()).expect("K05-M requires real Owner peers");
    converge(&mut world, "k05-member");
    let network = world.usb_host.hello_network.unwrap();
    assert!(network > u64::from(u32::MAX));
    let endpoint = ConsumerEndpoint::start(&world.provision.site.dir, network);
    world.usb_host.receive_state = Some(Arc::clone(&endpoint.state));
    world.peers[1].app_send(testkit::GATEWAY, b"member-st");
    world.pump_until(800, |_| false);
    let reply = endpoint.read(network, None);
    next_cursor(&reply);
    assert_eq!(records(&reply), 1);
}

#[test]
fn mesh_p06_k05_documented_consumer_commits_and_resumes() {
    let mut world = devram_world("p06-k05", Switch::direct());
    let network = world.usb_host.hello_network.unwrap();
    let endpoint = ConsumerEndpoint::start(&world.provision.site.dir, network);
    world.usb_host.receive_state = Some(Arc::clone(&endpoint.state));
    let db = world.provision.site.dir.join("consumer.db");
    let start = endpoint.read(network, None);
    let cursor_before_save = next_cursor(&start);
    for peer in [1, 2] {
        world.peers[peer].app_send(testkit::GATEWAY, b"st");
        world.pump_until(800, |_| false);
    }
    let first = endpoint.read(network, Some(&cursor_before_save));
    assert_eq!(records(&first), 2, "two real Owner messages");
    // A crash before storage keeps the old position and replays the same records.
    let replay = endpoint.read(network, Some(&cursor_before_save));
    assert_eq!(next_cursor(&first), next_cursor(&replay));
    assert_eq!(records(&replay), 2);
    assert!(endpoint
        .run_example(network, &db, Some(&cursor_before_save))
        .status
        .success());
    let committed = db_position(&db);
    assert_eq!(committed.0, 2);
    assert!(endpoint
        .run_example(network, &db, Some(&cursor_before_save))
        .status
        .success());
    assert_eq!(db_position(&db), committed, "replay persists no duplicate");
    // The consumer process restarts after commit and reads no duplicate/new record.
    assert!(endpoint.run_example(network, &db, None).status.success());
    assert_eq!(db_position(&db), committed);
    world.pump_until(2400, |_| false); // 60 s without consumer polling.
    assert_eq!(records(&endpoint.read(network, Some(&committed.1))), 0);
    // Advance production retention, not a separate consumer log model.
    endpoint
        .state
        .receive_log
        .lock()
        .unwrap()
        .read(network, 0, 32, now_ms() + 301_000, false);
    assert_eq!(
        error(&endpoint.read(network, Some(&cursor_before_save))),
        "CURSOR_GAP"
    );
    let failed = endpoint.run_example(network, &db, Some(&cursor_before_save));
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stdout).contains("CURSOR_GAP"));
    drop(endpoint);
    world.daemon_restart();
    let restarted = ConsumerEndpoint::start(&world.provision.site.dir, network);
    world.usb_host.receive_state = Some(Arc::clone(&restarted.state));
    assert_eq!(
        error(&restarted.read(network, Some(&committed.1))),
        "CURSOR_EPOCH_CHANGED"
    );
    // A post-restart failure preserves the previously durable cursor.
    let before = db_position(&db);
    assert!(!restarted.run_example(network, &db, None).status.success());
    assert_eq!(db_position(&db), before);
}

#[test]
#[ignore = "3-hop warm-up expires; tracked as K01-D red in scenarios.json"]
fn mesh_k01_display_periodic_load_and_api1_consumer() {
    let topology = Topology {
        nodes: 5,
        edges: vec![(0, 1), (1, 2), (1, 3), (2, 4)],
    };
    let world = devram_world("k01", Switch::new(&topology));
    display_load(world, [3, 4]);
}

#[test]
fn mesh_k01_display_direct_smoke() {
    display_load(devram_world("k01-direct", Switch::direct()), [1, 2]);
}

fn display_load(mut world: MeshWorld, members: [usize; 2]) {
    for member in members {
        let before = world.snaps[member].rx_count;
        world.peers[0].app_send(world.nodes[member], b"warm");
        world.pump_until(1600, |snaps| snaps[member].rx_count > before);
        assert!(
            world.snaps[member].rx_count > before,
            "warm-up route to {member}: {:?}",
            world.snaps[0].app_tx
        );
    }
    world.pump_until(400, |_| false);
    let network = world.usb_host.hello_network.unwrap();
    let endpoint = ConsumerEndpoint::start(&world.provision.site.dir, network);
    world.usb_host.receive_state = Some(Arc::clone(&endpoint.state));
    world.switch.set_noise(
        LegNoise {
            loss_ppm: 10_000,
            ..LegNoise::default()
        },
        21,
    );
    let mut cursor = next_cursor(&endpoint.read(network, None));
    let mut states = 0;
    let mut state_sends = 0;
    let mut seen = members.map(|member| world.snaps[member].rx_count);
    let mut last_view = [world.now; 2];
    let start = world.now;
    for tick in 0..12_000_u32 {
        if tick % 200 == 0 {
            for member in members {
                let mut body = tick.to_be_bytes().to_vec();
                if tick % 2400 == 0 {
                    body.resize(127, 0);
                }
                world.peers[0].app_send_with(world.nodes[member], 0, 21, &body);
            }
        }
        if tick % 600 == 0 {
            for member in members {
                world.peers[member].app_send(testkit::GATEWAY, b"st");
                state_sends += 1;
            }
        }
        // Change events, paced at 40/hour per endpoint (one every 90 s).
        if tick % 3600 == 0 {
            for member in members {
                world.peers[member].app_send(testkit::GATEWAY, b"tr");
                state_sends += 1;
            }
        }
        world.step(25);
        for (slot, member) in members.into_iter().enumerate() {
            if world.snaps[member].rx_count > seen[slot] {
                seen[slot] = world.snaps[member].rx_count;
                last_view[slot] = world.now;
            }
            assert!(
                world.now - last_view[slot] < 20_000,
                "view freshness at {} ms (member {member}, TX {:?})",
                world.now - start,
                world.snaps[0].app_tx
            );
        }
        if tick % 40 == 0 {
            let reply = endpoint.read(network, Some(&cursor));
            states += records(&reply);
            cursor = next_cursor(&reply); // This polling probe has no application side effect.
        }
    }
    world.pump_until(400, |_| false);
    states += records(&endpoint.read(network, Some(&cursor)));
    assert!(
        states * 1000 >= state_sends * 995,
        "state delivery {states}/{state_sends}"
    );
    assert!(
        world.switch.noise_hits.lost > 0,
        "seeded loss actually exercised"
    );
}
