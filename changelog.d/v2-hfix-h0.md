### Fixed

- A MemberEdhoc device that joined its first site without rebooting now
  applies revocation sets, removal notices and cutover grants. Before, these
  were ignored until the next reboot, so revocation and cutover never reached
  a freshly joined device.
- A field image on a board without BoardConfig now logs
  `CONFIG_REQUIRED: board configuration required` every 10 s and waits awake
  with the radio off. It no longer falls into the fail back-off, whose
  30-minute deep sleep made the USB port unavailable.
- The maintenance console no longer overflows its stack on ESP32-C6 after an
  identity is sealed. Its task stack is 16 KiB, and each reply logs the free
  stack.
- Mesh Lab headless provisioning now passes `provision-devcert` an identity
  spec that pins the lab Site CA, and it accepts `reference_node` bundles for
  boards that are not bridges.

### Changed

- `tools/hil/flash.py` refuses to write a signed field bundle to a board whose
  `rlcfg` partition is blank. Write the setup image and commit the
  BoardConfig first, or pass `--allow-unconfigured`.
