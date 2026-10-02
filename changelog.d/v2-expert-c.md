### Fixed

- HostLink now returns consumed receive credit in batches before it runs out,
  preventing USB queue drops during overlapping mesh ingress and delivery events.
- Compatibility documentation now lists `PT-4M-v2`, AuthorityEnvelope type 9,
  and the supported original Device API v1 struct prefixes. STATUS distinguishes
  merged v2 features from pending acceptance and hardware qualification.
