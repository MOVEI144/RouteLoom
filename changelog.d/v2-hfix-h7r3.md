### Fixed

- Release the ESP-NOW Owner CPU when a timer is due but no event is queued,
  pace refused Authority/RRS transfers, and respect the RRS gossip control gap.
  Dropped RX frames no longer create empty Owner wakes. Security, capacities,
  wire/storage formats, lifetimes and transmission attempt limits are unchanged.
