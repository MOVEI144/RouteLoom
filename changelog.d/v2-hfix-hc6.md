- Retry the final EDHOC link response on its original authenticated send leg
  within the existing budget, including when chunk deduplication suppresses
  repeated M3 delivery. Continue the bounded unbound-neighbour sweep after
  binding its first selected peer even if another OFFER was missed.
  Authentication, persistence, replay/dedup retention, capacities and request
  deadlines are unchanged. Physical qualification remains for the next HIL round.
