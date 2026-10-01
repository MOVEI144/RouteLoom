- Enable the C6 board RF switch (GPIO3 low) and select the internal antenna
  (GPIO14 low) before Device initializes Wi-Fi. Set
  `CONFIG_ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA=y` to select the external antenna.
  GPIO setup failures stop radio startup; C3, S3 and C5 are unchanged.
