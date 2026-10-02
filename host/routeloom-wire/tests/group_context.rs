use routeloom_wire::test_security::TestSecurity;
use routeloom_wire::*;

// Observe the production codec's provider boundary: the existing golden
// cipher does not use the extra group key-derivation inputs in its seed.
struct BoundSecurity {
    cipher: TestSecurity,
    expected: SecurityContext,
    checked: usize,
}

impl BoundSecurity {
    fn check(&mut self, context: &SecurityContext) {
        if matches!(
            context.scope,
            SecurityScope::Group | SecurityScope::GroupLink
        ) {
            assert_eq!(*context, self.expected);
            self.checked += 1;
        }
    }
}

impl SecurityProvider for BoundSecurity {
    fn ready(&self) -> bool {
        true
    }

    fn next_counter(&mut self, context: &SecurityContext) -> Result<u64> {
        self.check(context);
        self.cipher.next_counter(context)
    }

    fn seal(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_SIZE]> {
        self.check(context);
        self.cipher
            .seal(context, counter, aad, plaintext, ciphertext)
    }

    fn open(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AEAD_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<()> {
        self.check(context);
        self.cipher
            .open(context, counter, aad, ciphertext, tag, plaintext)
    }
}

#[test]
fn group_key_inputs_reach_the_provider_on_seal_and_open() {
    for scope in [SecurityScope::Group, SecurityScope::GroupLink] {
        let group = scope == SecurityScope::Group;
        let destination = if group {
            group::group_address(7)
        } else {
            BROADCAST_NODE_ID
        };
        let mut security = BoundSecurity {
            cipher: TestSecurity::new(),
            expected: SecurityContext {
                scope,
                network: 1,
                sender: 2,
                receiver: BROADCAST_NODE_ID,
                epoch: if group { 9 } else { 5 },
                group_epoch: if group { 0 } else { 9 },
                sender_boot: if group { 101 } else { 0 },
                group_id: if group { destination } else { 0 },
            },
            checked: 0,
        };
        let frame = PlainFrame {
            header: Header {
                frame_type: if group {
                    FrameType::GroupData
                } else {
                    FrameType::RouteUpdate
                },
                flags: if group { FLAG_END_PROTECTED } else { 0 },
                delivery: DeliveryClass::BestEffort,
                hop_remaining: 1,
                network: 1,
                origin: 2,
                destination,
                previous_hop: 2,
                next_hop: if group { 3 } else { BROADCAST_NODE_ID },
                message: MessageId {
                    session: 101,
                    sequence: 7,
                },
                link_epoch: 5,
                end_epoch: 9,
                remaining_deadline_ms: 5000,
                original_lifetime_ms: 5000,
                ..Header::default()
            },
            ..PlainFrame::default()
        };
        let mut encoded = EncodedFrame::default();
        encode_new(&frame, &mut security, &mut encoded).unwrap();
        let mut opened = LinkOpenedFrame::default();
        open_link(
            encoded.view(),
            frame.header.next_hop,
            &mut security,
            &mut opened,
        )
        .unwrap();
        if group {
            open_group(&opened, &mut security, &mut PlainFrame::default()).unwrap();
        }
        assert_eq!(security.checked, 3);
    }
}
