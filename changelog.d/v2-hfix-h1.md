### Changed

- `site.channel_plan.release` refuses with `NOT_READY` until every site
  member except the plan authority answered READY for the plan this daemon
  offered last. An offer drops the previous plan's report, and
  `site.channel_plan.status` shows the `required` count.
- A USB gateway hands each GATEWAY_SDK_RAM payload it received to its host
  as a mesh message, which frees the mailbox slot.

### Fixed

- A rebooted relay binds every live neighbour that answered its start
  discovery within seconds. Before, it bound the first and waited about 24 s
  for a rediscovery to bind the second (#167).
- A link handshake message whose exchange was superseded no longer holds the
  single link TX slot, which blocked every later chunked link handshake.
- A USB gateway no longer refuses explicit gateway sends with `CAPACITY`
  after eight GATEWAY_SDK_RAM receipts.
- A remote-config propose with a field of the wrong type for the SDK
  namespace is refused `INVALID` by the host instead of ending
  `INDETERMINATE`.
