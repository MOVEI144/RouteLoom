### Fixed

- Multi-hop MemberEdhoc End establishment retains the exchange until its
  existing 8 s deadline after the bounded EDHOC resends finish. Chunked
  replies over three or four hops can now arrive after the resend budget
  without losing the initiator's exchange. Link and resume timing is unchanged.
- Link exchange cost is sampled after pending hop exchanges settle, so a
  healthy submission awaiting HOP_ACCEPT does not inflate its metric and
  interrupt a multi-hop route. Failed attempt work and queue pressure still count.
- Real-Owner CI covers forced two-, three- and four-hop End sessions in
  DevRam and MemberEdhoc, including 100 Reliable messages (50 each way) over
  three hops and receipt/payload/duplicate checks without shortcut links.
