### Fixed

- Release the ESP-NOW Owner CPU when a timer is due but no event is queued,
  pace refused Authority/RRS transfers, and respect the RRS gossip control gap.
  Dropped RX frames no longer create empty Owner wakes. Security, capacities,
  wire/storage formats, lifetimes and transmission attempt limits are unchanged.

- Recover the first Reliable send after gateway reauthentication by avoiding
  duplicate handshakes with confirmed neighbors and promptly confirming a
  binding whose initial probe preceded the peer's context installation.
- Release the completed End handshake's crypto workspace while retaining its
  M4 retry evidence, and reject chunk receipts from a different peer.
