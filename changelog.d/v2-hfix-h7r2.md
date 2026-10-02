- Added TRACE-OFF/ON ESP-NOW callback-order and RX-overflow regressions through
  the real runtime and MeshNode.
- Fixed routed End handshake retry accounting: local route/pool admission
  refusals no longer consume the transmitted retry budget. Existing deadlines,
  retry cadence, admitted-send limit and retention remain unchanged. C6
  field-default delivery and gateway reset qualification remain incomplete.
