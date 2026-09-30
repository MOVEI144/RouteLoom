### Fixed

- Manual channel plan: a member that missed a plan switch (off the air at the
  release, or rebooted with an older stored plan) now finds the site again. With
  no bound neighbour for 15 s it listens in turn on its SitePackage channel and
  its plan channels (at most 3), stays where a neighbour authenticates, and
  adopts the site's newer signed plan there.
- Manual channel plan: the host no longer reuses the epoch of an offer that was
  never released, so a new offer after an aborted one is accepted.
- A node removed while it could not hear the removal notice (it learns the
  removal from its recovery join) can rejoin with the same NodeId after the
  holdoff, like a node that received the notice.
- A C3 gateway image whose capability bitmap names a feature compiled out of the
  image (for example node status on `gateway_small`) boots without advertising
  that bit instead of entering the fail streak and deep sleep.
- Gateway reset: a completed EDHOC exchange yields its crypto flight to a
  waiting exchange after traffic authenticates in the exact
  installed context. Retries of an unconfirmed m4 remain protected.
- HIL reset-cycle recovery time now measures the first observed delivery
  completion after reset, including its send latency.
- A confirmed link's EDHOC crypto flight now yields to another neighbour's
  link exchange, so that exchange need not wait for the completed flight's
  quiet timeout. Unconfirmed m4 retries still retain their evidence.
