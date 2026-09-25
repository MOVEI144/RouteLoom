use routeloom_wire::diagnostic_capability::{
    CAP_MEMBERSHIP_LIFECYCLE_V1, CAP_ROUTE_BROADCAST_V1, CAP_RRS_GOSSIP_V1, FEATURE_MASK,
};

#[test]
fn route_broadcast_and_rrs_are_distinct_wire_permissions() {
    assert_eq!(CAP_RRS_GOSSIP_V1, 1 << 5);
    assert_eq!(CAP_MEMBERSHIP_LIFECYCLE_V1, 1 << 6);
    assert_eq!(CAP_ROUTE_BROADCAST_V1, 1 << 7);
    assert_eq!(FEATURE_MASK, 0xff);
    assert_eq!(CAP_ROUTE_BROADCAST_V1 & CAP_RRS_GOSSIP_V1, 0);
}
