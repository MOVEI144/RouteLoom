use routeloom_wire::diagnostic_capability::{
    decode_query, decode_reply, encode_query, encode_reply, CapabilitiesReply,
    CAP_ROUTE_BROADCAST_V1, CAP_RRS_GOSSIP_V1,
};

#[test]
fn nonce_bound_query_reply_and_distinct_route_permission() {
    let nonce = [0xa5; 16];
    let query = encode_query(nonce).unwrap();
    assert_eq!(query.len(), 24);
    assert_eq!(decode_query(&query).unwrap(), nonce);
    let reply = CapabilitiesReply {
        echo_nonce: nonce,
        node_boot: 42,
        features: CAP_ROUTE_BROADCAST_V1 | CAP_RRS_GOSSIP_V1,
        permit_profiles: 1,
        valid_for_ms: 5000,
    };
    let encoded = encode_reply(reply).unwrap();
    assert_eq!(encoded.len(), 40);
    assert_eq!(decode_reply(&encoded).unwrap(), reply);
    // An old bit-5-only grant cannot identify a new broadcast sender: the
    // wire format has no discriminator for legacy RRS grants.
    let mut legacy = encoded;
    legacy[28..32].copy_from_slice(&CAP_ROUTE_BROADCAST_V1.to_be_bytes());
    assert_eq!(
        decode_reply(&legacy).unwrap().features,
        CAP_ROUTE_BROADCAST_V1
    );
}

#[test]
fn capability_body_rejects_noncanonical_fields() {
    let nonce = [1; 16];
    let mut query = encode_query(nonce).unwrap();
    query[20] = 1;
    assert!(decode_query(&query).is_err());
    query[20] = 0;
    query[4..20].fill(0);
    assert!(decode_query(&query).is_err());
    assert!(encode_query([0; 16]).is_err());
    let reply = CapabilitiesReply {
        echo_nonce: nonce,
        node_boot: 1,
        features: CAP_ROUTE_BROADCAST_V1,
        permit_profiles: 0,
        valid_for_ms: 15000,
    };
    let mut encoded = encode_reply(reply).unwrap();
    for (index, value) in [(0, 2), (1, 1), (2, 1), (3, 1), (27, 0), (28, 0x80), (35, 4)] {
        let old = encoded[index];
        encoded[index] = value;
        assert!(decode_reply(&encoded).is_err(), "index {index}");
        encoded[index] = old;
    }
    encoded[36..40].fill(0);
    assert!(decode_reply(&encoded).is_err());
    encoded[36..40].copy_from_slice(&15000_u32.to_be_bytes());
    assert!(decode_reply(&encoded[..39]).is_err());
    assert!(decode_reply(&[encoded.as_slice(), &[0]].concat()).is_err());
    assert!(encode_reply(CapabilitiesReply {
        valid_for_ms: 15001,
        ..reply
    })
    .is_err());
}
