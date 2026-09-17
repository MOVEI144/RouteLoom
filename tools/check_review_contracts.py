#!/usr/bin/env python3
"""Structural and selected semantic consistency checks, NOT firmware/RF qualification."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
import sync_reference_tables

EXPECTED_IDF_COMMIT='76f5dedd9950a3012fee8fb7d5586df21fc67802'

def validate(root: Path) -> dict:
    checks=[]
    def test(name,ok,detail=''):
        checks.append({'name':name,'passed':bool(ok),'detail':detail})
    def load(path):
        return json.loads((root/path).read_text(encoding='utf-8'))
    try:
        radio=load('docs/reference/radio-defaults.json')
        boards=load('docs/reference/boards.json')
        resources=load('docs/reference/resource-profiles.json')
        features=load('docs/reference/feature-profiles.json')
        semantic=load('protocol/semantics.json')
        test('idf_exact_pin',radio['esp_idf']=={'tag':'v6.0.3','commit':EXPECTED_IDF_COMMIT})
        test('fixed_baseline',radio['radio']['mode']=='LR250_FIXED' and radio['migration']['auto_policy'] is False)
        test('feature_status',all(f['implemented'] is False and f['qualified'] is False and f['default_enabled'] is False and f['evidence'] is None for f in features['features'].values()))
        test('wire_not_falsely_frozen',features['wire_frozen'] is False and semantic['wire_frozen'] is False and semantic['crypto_suite'] is None and semantic['frame_numeric_ids'] is None)
        test('initial_jitter_separate',radio['retry']['initial_data_jitter_ms']==[0,0] and radio['retry']['normal_jitter_scope']=='link-retry-only')
        test('semantic_security',semantic['counter_independent_of_message_id'] is True and semantic['applied_provider_failover_default'] is False and semantic['member_traffic_requires_roles_and_crypto'] is True)
        test('usb_credit_kind',semantic['usb_credit']=='session-direction-cumulative-grants')
        test('crc_profile',semantic['usb_crc']=='CRC-32/ISO-HDLC' and semantic['usb_crc_check_hex']=='CBF43926')
        test('frame_size_contract',semantic['max_normal_payload_bytes']==radio['buffers']['normal_payload_max']==128 and semantic['max_espnow_body_bytes']==radio['buffers']['espnow_body_max']==250)
        allow=semantic['membership_allowlist']; member_only=set(semantic['member_only'])
        test('no_nonmember_data',all(not(member_only & set(types)) for state,types in allow.items() if state!='MEMBER'))
        test('join_bootstrap_allowed',set(['BOOTSTRAP_AUTH','BOOTSTRAP_CHUNK','BOOTSTRAP_REPLY'])<=set(allow['AUTHENTICATING']))
        test('pending_result_fragment',set(['MEMBERSHIP_RESULT','BOOTSTRAP_CHUNK'])<=set(allow['AUTHORIZED_PENDING_COMMIT']))
        test('revoked_default_deny',allow['REVOKED']==[])
        test('aad_disjoint',not (set(semantic['end_immutable']) & set(semantic['hop_mutable'])))
        test('board_runtime_separate',boards['schema_version']==2 and all(b['published_facts_only'] is True and b['qualified_runtime_profile'] is None and b['runtime_generation_allowed'] is False for b in boards['boards']))
        for b in boards['boards']:
            if 'gpio_d0_to_d10' not in b:
                test('wio_conflict_defined',b['exclusive_functions']==[['base_user_led_gpio21','wio_button_gpio21']] and b['tcxo_voltage_v'] is None and b['rf_switch_polarity'] is None)
                continue
            text=(root/b['doc']).read_text(encoding='utf-8')
            rows=re.findall(r'^\|\s*D(\d+)\b[^|]*\|\s*(\d+)\s*\|',text,re.M)
            actual={int(k):int(v) for k,v in rows}
            test('pin_table:'+b['id'],actual==dict(enumerate(b['gpio_d0_to_d10'])))
        for name,p in resources['profiles'].items():
            budget=p['budget_bytes']
            test('typed_budget:'+name,all(type(v) is int and v>=0 for v in budget.values()))
            test('budget_total:'+name,sum(budget.values())<=p['sdk_budget_ceiling_bytes'])
            test('dedup_allocation:'+name,budget['dedup_and_compact_receipt_records']>=p['dedup_entries']*64)
            test('bounded_lifetime:'+name,p['max_message_lifetime_ms']==30000 and p['late_result_ttl_ms']==30000)
            test('unmeasured:'+name,p['qualified'] is False and p['measured_peak_bytes'] is None and p['voter_enabled'] is False)
        pre=resources['preauth']
        test('preauth_bounded',pre['global_handshakes']==1 and pre['max_object_bytes']<=pre['global_assembly_bytes'] and pre['max_object_bytes']<pre['authenticated_control_object_max_bytes'])
        test('preauth_cpu_budget',pre['asymmetric_operations_per_second']*pre['expensive_operation_max_ms']<=pre['cpu_budget_ms']<=pre['cpu_window_ms'])
        ad=resources['admission']
        test('atomic_reservation',ad['reservation_order']==['frame','dedup','transaction','reply_peer','ack_slot'] and ad['partial_reservation_side_effects'] is False)
        test('reply_peer_capacity',ad['reply_peer_leases_max']<=radio['peers']['transient'] and ad['protected_peers_including_regular_pin_max']<=radio['peers']['total']-radio['peers']['broadcast'])
        for error in sync_reference_tables.check(root):
            test('generated_table',False,error)
        test('generated_tables_match',not sync_reference_tables.check(root))
        disposition=load('docs/reference/review-disposition.json')
        test('all_findings_tracked',sorted(f['id'] for f in disposition['findings'])==list(range(1,31)))
        test('findings_not_falsely_closed',all(f['implementation_verified'] is False and f['remaining_gate'] and f['docs'] for f in disposition['findings']))
        for f in disposition['findings']:
            test(f"finding_paths:{f['id']}",all((root/p).is_file() for p in f['docs']))
    except (ValueError,KeyError,TypeError,OSError) as error:
        test('schema_read',False,str(error))
    return {'scope':'selected-design-contracts-and-document-consistency','checks':len(checks),'passed':sum(c['passed'] for c in checks),'failed':[c for c in checks if not c['passed']],'firmware_tested':False,'rf_tested':False}


def main():
    p=argparse.ArgumentParser(); p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]); p.add_argument('--report',type=Path); a=p.parse_args()
    result=validate(a.root); text=json.dumps(result,ensure_ascii=False,indent=2)
    print(text)
    if a.report: a.report.write_text(text+'\n',encoding='utf-8')
    return 1 if result['failed'] else 0

if __name__=='__main__':
    raise SystemExit(main())
