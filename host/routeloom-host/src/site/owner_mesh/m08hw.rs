//! M08 contention and receiver retention through real Device/Owner peers.

#[test]
fn mesh_m08hw_contention_within_terminal_quota() {
    super::uplink::star_burst(4, true, true);
}

#[test]
#[ignore = "40 accepted sends exceed unchanged 28 terminal pins; Reliable >=99% remains red"]
fn mesh_m08hw_contention_overload_small32() {
    super::uplink::star_burst(16, true, true);
}
