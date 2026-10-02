- Retry the final EDHOC link response on its original authenticated send leg
  within the existing budget, including when chunk deduplication suppresses
  repeated M3 delivery. Keep the bounded unbound-neighbour sweep through an
  overlapping repair and completed bind even if another OFFER was missed.
  Clear a failed hop’s old route hold on an authenticated relay restart even
  when link loss already removed its candidates.
  Authentication, persistence, replay/dedup retention, capacities and request
  deadlines are unchanged. Physical qualification remains for the next HIL round.
