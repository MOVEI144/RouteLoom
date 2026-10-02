### Fixed

- HostLink now returns consumed receive credit in batches before it runs out,
  preventing USB queue drops during overlapping mesh ingress and delivery events.
