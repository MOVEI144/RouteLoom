use routeloom_provision::sdkv1::lifecycle::{
    lifecycle_record_decode, lifecycle_record_encode, LifecycleMode, LifecycleRecord,
    LIFECYCLE_SEAL_COMMITTED,
};

#[test]
fn switching_is_one_sealed_intent_with_strict_lengths() {
    let mut record = LifecycleRecord {
        mode: LifecycleMode::Switching,
        self_node: 10,
        site_id: 7,
        old_network: 0x0001_0000_002a,
        new_network: 0x0002_0000_002a,
        generation: 2,
        rs_floor: 22,
        gk_floor: 19,
        boot_witness: 1,
        cutover_id: 4,
        revision: 1,
        payload: Vec::new(),
    };
    record.payload.extend_from_slice(&[0, 1, 0, 1, 0, 155]);
    record.payload.extend_from_slice(&[1, 2]);
    record.payload.extend_from_slice(&[3; 155]);
    record.payload.extend_from_slice(&[4; 32]);
    let bytes = lifecycle_record_encode(&record, LIFECYCLE_SEAL_COMMITTED, 2).unwrap();
    assert_eq!(
        lifecycle_record_decode(&bytes).unwrap(),
        (record.clone(), 2)
    );
    record.payload[5] = 154;
    assert!(lifecycle_record_encode(&record, LIFECYCLE_SEAL_COMMITTED, 2).is_err());
    record.payload[5] = 155;
    record.new_network = record.old_network;
    assert!(lifecycle_record_encode(&record, LIFECYCLE_SEAL_COMMITTED, 2).is_err());
}
