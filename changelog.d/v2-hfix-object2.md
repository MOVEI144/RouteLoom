- AppObject now makes progress while an unrelated Reliable send waits for a
  route. Ready control frames and hop confirmations keep priority;
  object airtime limits, authentication, deadlines and dedup retention are
  unchanged. A real-Owner regression covers 100 immediate transfers with
  1 Hz Reliable control and a continuously pending route wait.
