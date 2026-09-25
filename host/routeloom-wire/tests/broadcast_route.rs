use routeloom_wire::broadcast_route::{decode, encode, projected_metric, Record, INFINITY};

#[test]
fn parent_poison_and_whole_payload_validation() {
    let records = [
        Record {
            destination: 10,
            generation: 7,
            sequence: 3,
            metric: 0,
            via: 0,
        },
        Record {
            destination: 1,
            generation: 8,
            sequence: 4,
            metric: 5,
            via: 20,
        },
    ];
    let bytes = encode(&records, 10).unwrap();
    assert_eq!(bytes.len(), 52);
    assert_eq!(&bytes[..4], &[1, 0, 2, 0]);
    assert_eq!(
        &bytes[28..],
        &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 4, 0, 5, 0, 0, 0, 0, 0, 0, 0, 20]
    );
    assert_eq!(decode(&bytes, 10).unwrap(), records);
    assert_eq!(projected_metric(&records[1], 20), INFINITY);
    assert_eq!(projected_metric(&records[1], 30), 5);
    let mut bad = bytes.clone();
    bad[2] = 1;
    assert!(decode(&bad, 10).is_err());
    bad = bytes.clone();
    bad[3] = 1;
    assert!(decode(&bad, 10).is_err());
    bad = bytes.clone();
    bad[28..36].copy_from_slice(&bytes[4..12]);
    assert!(decode(&bad, 10).is_err());
    assert!(decode(&bytes[..51], 10).is_err());
}
