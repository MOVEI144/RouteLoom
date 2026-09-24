"""Negative contract examples. These do not execute ESP32, cryptography or Raft."""
import itertools
import json
from pathlib import Path
import sys
import unittest
import zlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from contract_models import (ContractError,PowerLoss,AtomicHighWater,CounterReservation,
    Credit,Idempotency,admit,permit_frame,resume_deadline,provider_failover_allowed,
    feasible,advertise_fd,seq_newer,metric_add,runtime_board,MAX64)
S=json.loads((ROOT/'protocol/semantics.json').read_text())

class BootstrapTests(unittest.TestCase):
    def test_pre_member_data_denied(self):
        for state in S['membership_allowlist']:
            if state!='MEMBER':
                for kind in S['member_only']:
                    self.assertFalse(permit_frame(S,state,kind,peer_member=True,authenticated=True,authorized=True))
    def test_authentication_exchange_is_possible(self):
        self.assertTrue(permit_frame(S,'AUTHENTICATING','BOOTSTRAP_AUTH',bootstrap_transaction=True))
        self.assertTrue(permit_frame(S,'AUTHENTICATING','BOOTSTRAP_CHUNK',bootstrap_transaction=True))
    def test_unrelated_bootstrap_denied(self):
        self.assertFalse(permit_frame(S,'AUTHENTICATING','BOOTSTRAP_CHUNK'))
    def test_pending_membership_fragment(self):
        self.assertTrue(permit_frame(S,'AUTHORIZED_PENDING_COMMIT','BOOTSTRAP_CHUNK',bootstrap_transaction=True))
    def test_proxy_does_not_admit_nonmember_data(self):
        self.assertFalse(permit_frame(S,'MEMBER','DATA',authenticated=True,authorized=True))
    def test_member_role_and_auth_are_separate(self):
        self.assertFalse(permit_frame(S,'MEMBER','ROUTE_UPDATE',peer_member=True,authenticated=True))
        self.assertTrue(permit_frame(S,'MEMBER','ROUTE_UPDATE',peer_member=True,authenticated=True,authorized=True))
    def test_revoked_cannot_resume(self):
        self.assertFalse(permit_frame(S,'REVOKED','BOOTSTRAP_AUTH',bootstrap_transaction=True))

class CrashTests(unittest.TestCase):
    def test_no_send_before_reservation_commit(self):
        store=AtomicHighWater(); alloc=CounterReservation(store,4)
        with self.assertRaises(PowerLoss): alloc.next('before')
        self.assertEqual(store.end,0)
        self.assertEqual(CounterReservation(store,4).next(),0)
    def test_lost_commit_ack_burns_range(self):
        store=AtomicHighWater(); alloc=CounterReservation(store,4)
        with self.assertRaises(PowerLoss): alloc.next('after')
        self.assertEqual(store.end,4)
        self.assertEqual(CounterReservation(store,4).next(),4)
    def test_cold_restart_does_not_reuse_unused_range(self):
        store=AtomicHighWater(); alloc=CounterReservation(store,4)
        self.assertEqual(alloc.next(),0)
        self.assertEqual(CounterReservation(store,4).next(),4)
    def test_all_short_send_restart_sequences(self):
        for actions in itertools.product(('send','restart'),repeat=8):
            store=AtomicHighWater(); alloc=CounterReservation(store,4); sent=[]
            for action in actions:
                if action=='send': sent.append(alloc.next())
                else: alloc=CounterReservation(store,4)
            self.assertEqual(len(sent),len(set(sent)))
    def test_corrupt_store_blocks_context(self):
        with self.assertRaises(ContractError): CounterReservation(AtomicHighWater(4,False))
    def test_counter_exhaustion_does_not_wrap(self):
        with self.assertRaises(ContractError): CounterReservation(AtomicHighWater(MAX64-2),4).next()
    def test_unknown_elapsed_time_holds(self):
        self.assertEqual(resume_deadline(5000,None),('TIME_UNCERTAIN',None))
    def test_worst_case_elapsed_time_used(self):
        self.assertEqual(resume_deadline(5000,(10,100)),('READY',4900))
    def test_next_day_command_expires(self):
        self.assertEqual(resume_deadline(5000,(86400000,86400001)),('EXPIRED',0))
    def test_invalid_clock_range_rejected(self):
        with self.assertRaises(ContractError): resume_deadline(5000,(100,1))

class AdmissionTests(unittest.TestCase):
    ORDER=('frame','dedup','transaction','reply_peer','ack_slot')
    def test_failure_at_every_reservation_rolls_back(self):
        for where in self.ORDER:
            capacities=dict.fromkeys(self.ORDER,1); before=capacities.copy()
            self.assertIsNone(admit(capacities,self.ORDER,where))
            self.assertEqual(capacities,before)
    def test_peer_exhaustion_no_receive_side_effect(self):
        capacities=dict.fromkeys(self.ORDER,2); capacities['reply_peer']=0; before=capacities.copy()
        self.assertIsNone(admit(capacities,self.ORDER)); self.assertEqual(capacities,before)
    def test_success_consumes_each_resource_once(self):
        capacities=dict.fromkeys(self.ORDER,1)
        self.assertEqual(admit(capacities,self.ORDER),self.ORDER)
        self.assertEqual(sum(capacities.values()),0)
    def test_applied_failover_defaults_to_no(self):
        self.assertFalse(provider_failover_allowed('APPLIED',False))
        self.assertFalse(provider_failover_allowed('APPLIED',True))
    def test_applied_failover_needs_effect_policy(self):
        self.assertTrue(provider_failover_allowed('APPLIED',True,shared_idempotency=True))
        self.assertTrue(provider_failover_allowed('APPLIED',True,duplicate_effect_ok=True))

class USBTests(unittest.TestCase):
    def test_crc_known_vector(self):
        self.assertEqual(zlib.crc32(b'123456789'),int(S['usb_crc_check_hex'],16))
    def test_duplicate_grant_not_additive(self):
        c=Credit('s'); c.grant('s',4,400,True); c.grant('s',4,400,True)
        for _ in range(4): c.begin(100)
        with self.assertRaises(ContractError): c.begin(1)
    def test_stale_grant_ignored(self):
        c=Credit('s'); c.grant('s',4,400,True); c.grant('s',1,100,True)
        self.assertEqual((c.grant_frames,c.grant_bytes),(4,400))
    def test_golden_stale_grants_replay(self):
        # protocol/usb-golden: the C++ bridge and Rust codec replay the same
        # tx_grant/tx_grant_stale/tx_grant_zero/tx_grant_mixed notices — the
        # contract model must agree on the per-axis-max outcome (20, 65536).
        frames_dir=ROOT/'protocol/usb-golden/frames'
        vectors=sorted(frames_dir.glob('*.json'))
        self.assertGreaterEqual(len(vectors),10)
        c=Credit('dev-session')
        grants=0
        for path in vectors:
            v=json.loads(path.read_text())
            inner=bytes.fromhex(v.get('inner_hex',''))
            if v['direction']=='h2d' and v['kind']==32 and len(inner)==17 and inner[0]==0:
                frames=int.from_bytes(inner[1:9],'big')
                octets=int.from_bytes(inner[9:17],'big')
                c.grant('dev-session',frames,octets,True)
                grants+=1
        self.assertEqual(grants,4)  # tx_grant + stale + zero + mixed
        self.assertEqual((c.grant_frames,c.grant_bytes),(20,65536))
    def test_session_change_blocks_old_credit(self):
        c=Credit('new')
        with self.assertRaises(ContractError): c.grant('old',4,400,True)
        self.assertEqual(c.grant_frames,0)
    def test_unauthenticated_credit_blocked(self):
        with self.assertRaises(ContractError): Credit('s').grant('s',4,400,False)
    def test_partial_write_charged_only_once(self):
        c=Credit('s'); c.grant('s',1,100,True); token=c.begin(100)
        for _ in range(100): c.continue_write(token)
        c.finish(token); self.assertEqual((c.consumed_frames,c.consumed_bytes),(1,100))
    def test_both_credit_dimensions_enforced(self):
        c=Credit('s'); c.grant('s',3,100,True)
        with self.assertRaises(ContractError): c.begin(101)
        self.assertEqual(c.consumed_frames,0)
    def test_invalid_credit_does_not_overflow(self):
        for amount in [-1,MAX64+1,True]:
            with self.assertRaises(ContractError): Credit('s').grant('s',amount,100,True)
    def test_idempotency_scope(self):
        x=Idempotency()
        for principal,net,kind in [('a','n','send'),('b','n','send'),('a','m','send'),('a','n','config')]:
            self.assertEqual(x.submit(principal,net,kind,'42','h'),'ACCEPTED')
        self.assertEqual(x.submit('a','n','send','42','h'),'EXISTING')
    def test_same_identity_different_payload_conflict(self):
        x=Idempotency(); x.submit('a','n','send','42','h')
        with self.assertRaises(ContractError): x.submit('a','n','send','42','other')

class RoutePredicateTests(unittest.TestCase):
    def test_triangle_needs_new_sequence(self):
        fd=(137,1)
        self.assertFalse(feasible(137,2,fd))
        self.assertTrue(feasible(138,2,fd))
    def test_fd_tracks_sent_finite_advertisements(self):
        fd=advertise_fd(137,1,None)
        self.assertEqual(advertise_fd(137,3,fd),(137,1))
        self.assertEqual(advertise_fd(138,3,fd),(138,3))
    def test_withdraw_does_not_erase_frontier(self):
        self.assertEqual(advertise_fd(138,65535,(137,1)),(137,1))
    def test_sequence_wrap_and_half_range(self):
        self.assertTrue(seq_newer(0,65535))
        self.assertFalse(seq_newer(65535,0))
        with self.assertRaises(ContractError): seq_newer(32768,0)
    def test_metric_positive_and_saturated(self):
        self.assertEqual(metric_add(65534,100),65535)
        with self.assertRaises(ContractError): metric_add(1,0)

class BoardTests(unittest.TestCase):
    def test_published_boards_are_not_runtime_profiles(self):
        boards=json.loads((ROOT/'docs/reference/boards.json').read_text())['boards']
        for b in boards:
            with self.assertRaises(ContractError): runtime_board(b,set())
    def test_gpio21_collision_even_with_hypothetical_qualification(self):
        board={'runtime_generation_allowed':True,'qualified_runtime_profile':{},'exclusive_functions':[['led','button']]}
        with self.assertRaises(ContractError): runtime_board(board,{'led','button'})

if __name__=='__main__': unittest.main()
