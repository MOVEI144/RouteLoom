# Build evidence

Each directory contains the ESP-IDF v6.0.3 build log, requested Kconfig lines,
redacted resolved `sdkconfig`, static RAM report, size report, and SHA-256 sums.
Raw `.bin` images and unredacted `sdkconfig` files remain in the ignored local
`artifacts/hil/2026-09-26/images/full-r*/` directories.

The `full-r7-member-timing-*` and `full-r7-member-sleep-*` reference images
used UART0 logging and were not flashed. `full-r8-member-*` enables USB
Serial/JTAG logging for the join, cryptographic timing, and sleep trials.
`full-r7-member-group-bridge` is the bridge image for those trials.

The 25 current CI firmware cells were rebuilt after the fixes. Their build
logs and RAM reports are in `../ci-matrix-25-logs/`, with the cell outcome
list in `../ci-matrix-25.json`; raw `full-r9-ci-*` images stay ignored locally.

R2's `full-r14`, `full-r15`, and `full-r17`–`full-r20` entries use the same redaction. `full-r18`
and `full-r19` route application logs to USB only for isolated cutover
diagnosis; `full-r20` restores the production UART0 console. The final C3/S3/C5
matrix evidence is in `../r2/ci-matrix-25-adoptionfix.json`; its raw images
remain ignored locally.
