use routeloom_wire::{validate_header, DeliveryClass, FrameType, Header, BROADCAST_NODE_ID};

fn header() -> Header {
    Header {
        network: 1,
        origin: 2,
        destination: 3,
        previous_hop: 2,
        next_hop: 3,
        original_lifetime_ms: 5000,
        remaining_deadline_ms: 5000,
        ..Header::default()
    }
}

#[test]
fn extension_variant_cannot_emit_unregistered_ids() {
    for id in [0, 8, 16, 25, 32, 63, 96, 255] {
        let mut h = header();
        h.frame_type = FrameType::Extension(id);
        assert!(validate_header(&h).is_err(), "extension id {id}");
    }
    for id in 64..=95 {
        let mut h = header();
        h.frame_type = FrameType::Extension(id);
        assert!(validate_header(&h).is_ok(), "extension id {id}");
    }
}

#[test]
fn broadcast_route_header_has_the_cpp_receive_contract() {
    let mut h = header();
    h.destination = BROADCAST_NODE_ID;
    h.next_hop = BROADCAST_NODE_ID;
    assert!(validate_header(&h).is_err());
    h.frame_type = FrameType::RouteUpdate;
    h.delivery = DeliveryClass::BestEffort;
    h.hop_remaining = 1;
    assert!(validate_header(&h).is_ok());
    h.previous_hop = 4;
    assert!(validate_header(&h).is_err());
}
