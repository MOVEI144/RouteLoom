### Fixed

- The K02 31-node load model now reports a skip when the selected resource
  profile cannot hold its gateway routes, including the endpoint profile's
  16-entry leaf table. Profiles with sufficient routing capacity keep the
  existing freshness, delivery and airtime limits.
