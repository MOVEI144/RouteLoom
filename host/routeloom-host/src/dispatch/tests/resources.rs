use super::*;
use crate::send_store::{EPOCH_WINDOW_MS, RETENTION_MS};

#[test]
fn reclaimed_operations_release_retry_history_on_the_same_lease() {
    let mut store = MemoryOperationStore::new([7; 16]);
    let mut dispatcher = Dispatcher::new([7; 16]);
    let seq = admitted(&mut store, 0x11, 30_000, 1_000);
    let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
    let attempted = dispatcher.last_attempt[&seq];
    dispatcher.tick(&mut store, &link(), 1_011);
    assert_eq!(dispatcher.last_attempt.get(&seq), Some(&attempted));
    let hash = op(&store, seq).hash;
    dispatcher.handle_reply(
        &mut store,
        submit.request,
        &receipt(
            host_ops::SUB_SUBMIT,
            HostOpsResult::Ok,
            SlotState::Delivered,
            1,
            Evidence::EndSdkReceived,
            hash,
        ),
        1_050,
    );
    // Close the admission epoch, then advance past the result's protection
    // window. Store reclamation must also reclaim the dispatcher's cache.
    store
        .open_epoch((UID, NET), 1_000 + EPOCH_WINDOW_MS)
        .unwrap();
    let now = 1_051 + RETENTION_MS + EPOCH_WINDOW_MS;
    store.open_epoch((UID, NET), now).unwrap();
    assert!(store.get_by_seq(seq).unwrap().is_none());
    let lease_before = dispatcher.lease;
    dispatcher.tick(&mut store, &link(), now);
    assert_eq!(dispatcher.lease, lease_before);
    assert!(dispatcher.last_attempt.is_empty());
}
