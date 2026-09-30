### Changed

- `site.channel_plan.release` refuses with `NOT_READY` until every site
  member except the plan authority answered READY for the plan this daemon
  offered last. An offer drops the previous plan's report, and
  `site.channel_plan.status` shows the `required` count. The gateway checks
  each required member ID against READY for that plan before releasing.
  The HostOps 0x68 RELEASE payload now carries the required member IDs
  (up to 8), so the host and the gateway firmware must be updated together:
  a mismatched pair fails closed (the gateway refuses the RELEASE with
  `PROTOCOL_ERROR` and the commit stays held).
- A USB gateway hands each GATEWAY_SDK_RAM payload to its host and frees the
  mailbox slot after ReceiveLog storage is confirmed. An unacknowledged
  payload remains readable after USB session loss until its 60 s expiry.

### Fixed

- A rebooted relay binds every live neighbour that answered its start
  discovery within seconds. Before, it bound the first and waited about 24 s
  for a rediscovery to bind the second (#167).
- A link handshake message whose exchange was superseded no longer holds the
  single link TX slot, which blocked every later chunked link handshake.
- A USB gateway no longer refuses explicit gateway sends with `CAPACITY`
  after eight GATEWAY_SDK_RAM receipts.
- A USB gateway refuses new SDK_RAM work with `HOST_UNAVAILABLE` while its
  host reader is absent, instead of accepting mail that no app can drain.
- A channel cutover recovers a fenced ESP-NOW send whose driver callback never
  arrives; the peer is no longer blocked indefinitely by that fence.
- A remote-config propose with a field of the wrong type for the SDK
  namespace is refused `INVALID` by the host instead of ending
  `INDETERMINATE`.
- A legacy SEND without a terminal delivery event ends as `indeterminate`
  after its mesh lifetime plus the host event allowance.
