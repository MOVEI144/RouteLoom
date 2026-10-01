- Enable the C6 board RF switch (GPIO3 low) and select the internal antenna
  (GPIO14 low) before Device initializes Wi-Fi. Set
  `CONFIG_ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA=y` to select the external antenna.
  GPIO setup failures stop radio startup; C3, S3 and C5 are unchanged.
- Account for the RF GPIO driver in C6 radio-image flash budgets (+704 B
  measured on the reference image against `4a931258`). Static RAM grows by
  40 B; RAM floors, partition limits and drift allowances are unchanged.
