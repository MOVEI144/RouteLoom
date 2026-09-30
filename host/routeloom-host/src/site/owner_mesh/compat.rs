//! Product-compatibility rows over the real Owners: wire forward
//! compatibility inside major 2 (tests/e2e/scenarios.json P04).

use super::mesh::deliver_each;
use super::*;

const WIRE_EXTENSION_90: u8 = 90;

/// P04: A (behind relay B) seals, with its live sessions toward the
/// gateway, an extension-type frame (90) with a Bulk traffic hint and a
/// minor-1 DATA whose traffic byte has reserved bits set. B forwards both
/// with type, minor and traffic unchanged; the gateway authenticates the
/// extension frame and refuses it as UNSUPPORTED (never accepted as data),
/// and delivers the minor-1 DATA to its application.
#[test]
fn mesh_p04_extension_and_newer_minor_cross_a_relay() {
    let Some(mut world) = MeshWorld::start("p04", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "p04");
    // A real DATA brings the A–G end session up before anything is sealed.
    deliver_each(&mut world, 1, 0, 1, b"p04-warm");
    let mac_a = world.macs[1];
    let mac_b = world.macs[2];

    world.switch.watch_kind = Some(WIRE_EXTENSION_90);
    let rx_before = world.snaps[0].rx_count;
    let ext = world.peers[1].craft_frame(
        NODE_B,
        testkit::GATEWAY,
        WIRE_EXTENSION_90,
        0,
        1,
        b"extension-90",
    );
    world.peers[2].send_rx(&mac_a, &mac_b, &ext);
    world.pump_until(400, |snaps| snaps[0].ext_unsupported >= 1);
    assert!(
        world.snaps[0].ext_unsupported >= 1,
        "the gateway refused the extension frame as UNSUPPORTED: {:?}",
        world.snaps[0]
    );
    let forwarded: Vec<&Vec<u8>> = world
        .switch
        .watched
        .iter()
        .filter(|(from, to, _)| *from == 2 && *to == 0)
        .map(|(_, _, header)| header)
        .collect();
    assert!(!forwarded.is_empty(), "B forwarded the extension frame");
    assert!(forwarded
        .iter()
        .all(|h| h[4] == WIRE_EXTENSION_90 && h[3] == 0 && h[9] == 1 && h[5] == 1));
    assert_eq!(
        world.snaps[0].rx_count, rx_before,
        "never delivered as data"
    );

    world.switch.watch_kind = Some(WIRE_DATA);
    world.switch.watched.clear();
    let data =
        world.peers[1].craft_frame(NODE_B, testkit::GATEWAY, WIRE_DATA, 1, 0xFD, b"minor-one");
    world.peers[2].send_rx(&mac_a, &mac_b, &data);
    world.pump_until(400, |snaps| snaps[0].rx_count > rx_before);
    assert_eq!(
        world.snaps[0].rx_count,
        rx_before + 1,
        "minor-1 DATA delivered once"
    );
    assert_eq!(world.snaps[0].rx, b"minor-one");
    assert!(world
        .switch
        .watched
        .iter()
        .any(|(from, to, h)| *from == 2 && *to == 0 && h[3] == 1 && h[9] == 0xFD));
    // The relay path still carries ordinary traffic afterwards.
    deliver_each(&mut world, 1, 0, 3, b"p04-after");
}
