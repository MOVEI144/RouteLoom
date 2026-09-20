#!/usr/bin/env python3
"""Design lint and serialization examples; NOT runtime, RF or security qualification."""
from __future__ import annotations
import argparse
import copy
import hashlib
import hmac
import json
import re
import struct
from pathlib import Path
from urllib.parse import unquote, urlsplit

DESIGN = Path('docs/design/scope-gateway-config')


def contract_errors(c: dict) -> list[str]:
    errors: list[str] = []
    def require(ok: bool, name: str) -> None:
        if not ok:
            errors.append(name)
    try:
        require(c['design_version'] == '0.1-draft', 'design version')
        require(all(c[k] is False for k in ('runtime_implemented', 'hardware_tested', 'qualified', 'runtime_default_changes')), 'maturity unchanged')
        require(c['issues'] == [14,16,17], 'issue scope')
        w,s,g,f,u = (c[k] for k in ('wire','scope','gateway','config','usb'))
        require(w['header_bytes'] == 88 and w['tag_bytes'] == 16 and w['application_max'] == 128, 'wire v1 budget')
        require(w['header_bytes'] + w['application_max'] + 2*w['tag_bytes'] == w['normal_max'] == 248 <= w['body_max'] == 250, 'wire accounting')
        require(w['network_supported_max'] == 0xffffffff, 'network width')
        require([w[k] for k in ('service_type','control_type','manifest_type','chunk_type','ack_type','config_object_kind')] == [21,22,49,50,51,3], 'type registry')
        require(s['key_bytes'] == 32 and s['tag_bytes'] == 16, 'scope strength')
        require(s['rld_header'] == 44 and s['body_version'] == 2 and s['scheme'] == 1, 'scope version')
        require(s['discover_prefix']+s['tag_bytes']==s['discover_body']==24, 'discover layout')
        require(s['offer_prefix']+s['tag_bytes']==s['offer_body']==60, 'offer layout')
        require(s['rld_header']+s['offer_body']<=s['rld_total_max']==160, 'RLD limit')
        require(s['active_scopes']==1 and s['key_generations']==2, 'bounded keys')
        require(s['dedup_records']==32 and s['dedup_ttl_ms']==8000, 'scope dedup')
        require(not s['required_fallback'] and not s['grants_membership'], 'scope authorization boundary')
        require(s['previous_overlap_max_ms']<=1800000 and s['legacy_attempts_max']==1 and s['legacy_migration_max_ms']<=86400000, 'rotation bounds')
        require(g['submit_prefix']+g['payload_max']==128 and g['payload_max']==96, 'gateway payload')
        require(g['query_bytes']==52 and g['descriptor_bytes']==86 and g['outcome_bytes']==84, 'service layouts')
        arrivals=(g['accepted_per_minute']*g['receipt_hold_ms']+59999)//60000+g['burst']
        require(arrivals+g['capacity_margin']<=g['receipt_records']==32, 'gateway capacity')
        require(g['pending_max']<=g['receipt_records'] and g['endpoint_records']==4, 'gateway pending')
        require(g['message_lifetime_max_ms']*2<=g['receipt_hold_ms'], 'receipt lifetime')
        require(0<g['renew_ms']<g['lease_ms']==15000, 'endpoint lease')
        require(not g['identity_failover'] and g['host_receipt_requires_insert_ack'] and not g['host_independent_signature'], 'gateway evidence')
        require(f['canonical_header']==176 and f['patch_max']==512, 'config canonical')
        require(f['canonical_header']+f['patch_max']+f['cose_overhead_max']==f['permit_encoded_max']==774<=f['object_max']==1024, 'signed object size')
        require(w['chunk_prefix']+w['chunk_data']==128 and w['chunk_data']==90, 'chunk size')
        require(f['field_count_max']==16 and f['field_value_max']==96, 'patch bounds')
        records=(f['accepted_per_minute']*f['result_hold_ms']+59999)//60000+f['transactions_per_target']+f['burst']
        require(records<=f['records']==8 and f['result_hold_ms']>=300000, 'config capacity')
        require(f['challenge_max_ms']==30000 and f['reassembly_timeout_ms']<=f['challenge_max_ms'], 'config time')
        require(f['slots_per_namespace']==2 and f['slot_bytes']>=2*f['snapshot_max']+f['object_max']+512, 'config journal size')
        require(not any(f[k] for k in ('global_sequence_equals_target_revision','scope_key_authorizes_config','auto_reset_corrupt_revision')), 'config boundaries')
        require(u['frame_kind']==19 and u['gateway_subtypes']==[16,17,18,19] and u['config_subtypes']==[32,33,34,35], 'USB registry')
        require(u['gateway_capability_bit']==3 and u['config_capability_bit']==4 and u['ordinary_credit'], 'USB capabilities/credit')
        require(u['ingress_payload_max']==32+20+32+96 and u['ingress_frame_body_max']==u['ingress_payload_max']+4==184, 'USB ingress accounting')
        require(u['canonical_v2_max']==26+34+96 and u['host_submit_v2_max']==u['canonical_v2_max']+u['host_submit_fixed']==264, 'USB submit accounting')
        require(c['acceptance']=={'scenario_count':46,'status':'planned_not_run','executed_runtime_scenarios':0}, 'unexecuted inventory')
    except (KeyError, TypeError, ValueError) as exc:
        errors.append('schema: '+str(exc))
    return errors


def gateway_decode(data: bytes) -> bytes:
    if len(data)<32:
        raise ValueError('short')
    v,sub,scope,flags,token,boot,length,reserved=struct.unpack('>BBBB16sQHH', data[:32])
    if v!=1 or sub!=3 or scope not in (1,2) or flags or reserved or not any(token) or not boot or length>96 or len(data)!=32+length:
        raise ValueError('invalid')
    return data[32:]


def cbor_bytes(data: bytes) -> bytes:
    n=len(data)
    if n<24:
        return bytes([0x40+n])+data
    if n<256:
        return bytes([0x58,n])+data
    return b'\x59'+struct.pack('>H',n)+data


def run(root: Path) -> dict:
    d=root/DESIGN
    c=json.loads((d/'contracts.json').read_text())
    ex=json.loads((d/'examples.json').read_text())
    cs=json.loads((d/'cases.json').read_text())
    issues=contract_errors(c)
    checks: list[str] = []
    def check(ok: bool, name: str) -> None:
        checks.append(name)
        if not ok:
            issues.append(name)
    markdown=sorted(d.glob('*.md'))
    check(len(markdown)==10, 'ten design documents')
    links=0
    for file in markdown:
        text=file.read_text(encoding='utf-8')
        check(text.startswith('# ') and text.endswith('\n'), 'text:'+file.name)
        check(len(re.findall(r'^```',text,re.M))%2==0, 'fences:'+file.name)
        clean=re.sub(r'```.*?```','',text,flags=re.S)
        for target in re.findall(r'\]\(([^\s)]+)\)',clean):
            parsed=urlsplit(target)
            if parsed.scheme or not parsed.path:
                continue
            candidate=(file.parent/unquote(parsed.path)).resolve()
            check(candidate.is_relative_to(root.resolve()) and candidate.exists(), 'link:'+file.name+':'+target)
            links+=1
    check(cs['status']=='planned_not_run' and len(cs['cases'])==46, 'scenario inventory')
    expected={f'{letter}{n:02}' for letter,count in [('S',12),('G',12),('C',14),('I',8)] for n in range(1,count+1)}
    check({x['id'] for x in cs['cases']}==expected and len(cs['cases'])==len(expected), 'case IDs')
    check(all(all(x.get(k) for k in ('area','setup','action','expect')) for x in cs['cases']), 'case detail')
    s=c['scope']; f=ex['scope']; key=bytes(range(32))
    dp=bytes.fromhex(f['discover_hex']);op=bytes.fromhex(f['offer_hex'])
    network=struct.pack('>Q',f['network']);src=bytes.fromhex(f['requester_mac_hex']);dst=bytes.fromhex(f['responder_mac_hex'])
    hint=hmac.digest(key,s['hint_domain'].encode()+bytes([f['scope_class']])+network+struct.pack('>I',f['generation']),'sha256')[:4]
    check(int.from_bytes(hint,'big')==f['hint'] and dp[12:16]==hint and op[12:16]==hint, 'scope hint')
    for packet,kind,size in ((dp,1,68),(op,2,104)):
        magic,v,k,hl,total,flags=struct.unpack('>4sBBHHH',packet[:12])
        check((magic,v,k,hl,total,flags)==(b'RLD1',1,kind,44,size,0) and len(packet)==size, f'RLD header {kind}')
    din=network+src+b'\xff'*6+dp[:-16]
    oin=network+src+dst+hashlib.sha256(dp).digest()+op[:-16]
    check(hmac.compare_digest(hmac.digest(key,s['discover_domain'].encode()+din,'sha256')[:16], dp[-16:]), 'discover tag')
    check(hmac.compare_digest(hmac.digest(key,s['offer_domain'].encode()+oin,'sha256')[:16], op[-16:]), 'offer tag')
    check(hashlib.sha256(dp).hexdigest()==f['discover_digest_hex'] and hashlib.sha256(op).hexdigest()==f['offer_digest_hex'], 'scope digests')
    check(dp[44:52]==struct.pack('>BBBBI',2,1,1,0,7) and op[80:88]==struct.pack('>BBHI',1,1,0,7), 'scope prefixes')
    rfc=ex['hmac_rfc4231_case1']
    check(hmac.digest(bytes.fromhex(rfc['key_hex']),bytes.fromhex(rfc['data_hex']),'sha256').hex()==rfc['sha256_hex'], 'RFC4231 case1')
    for row in ex['gateway_submits']:
        check(gateway_decode(bytes.fromhex(row['encoded_hex']))==bytes.fromhex(row['payload_hex']), 'gateway:'+row['id'])
    rejected=0
    for row in ex['invalid_gateway']:
        try:
            gateway_decode(bytes.fromhex(row['encoded_hex']))
        except ValueError:
            rejected+=1
        else:
            issues.append('accepted invalid gateway '+row['id'])
    check(rejected==4,'four invalid gateway examples')
    cf=json.loads((d/'config-example.json').read_text())
    raw=bytes.fromhex(cf['canonical_hex']);patch=bytes.fromhex(cf['patch_hex']);old=bytes.fromhex(cf['old_snapshot_hex'])
    check(raw[:4]==b'RCC1' and len(raw)==176+len(patch) and raw[176:]==patch and not cf['valid_signature'], 'config canonical example')
    check(struct.unpack_from('>QQ',raw,64)==(7,8) and struct.unpack_from('>IHH',raw,168)==(5000,len(patch),0), 'config revision/time/length')
    base=lambda x: hashlib.sha256(b'RouteLoom/config-snapshot/v1\0'+struct.pack('>HH',1,1)+x).digest()
    check(raw[80:112]==base(old) and raw[112:144]==base(patch), 'config snapshot hashes')
    # Shape/size only: the zero signature is deliberately NOT a valid signature.
    protected=b'\xa2\x01\x26\x04\x48'+bytes(8)
    cose=b'\xd2\x84'+cbor_bytes(protected)+b'\xa0'+cbor_bytes(bytes(688))+cbor_bytes(bytes(64))
    check(len(cose)==774, 'COSE maximum shape (not signature validation)')
    check(all(x['v']==1 and x['method'] in ('gateway.resolve','config.propose') for x in ex['api_examples']), 'API example framing')
    mutations=[(('runtime_implemented',),True),(('qualified',),True),(('scope','tag_bytes'),12),(('scope','required_fallback'),True),(('scope','grants_membership'),True),(('scope','key_generations'),99),(('wire','network_supported_max'),2**64-1),(('gateway','payload_max'),128),(('gateway','receipt_records'),16),(('gateway','identity_failover'),True),(('gateway','host_receipt_requires_insert_ack'),False),(('config','scope_key_authorizes_config'),True),(('config','global_sequence_equals_target_revision'),True),(('config','auto_reset_corrupt_revision'),True),(('config','object_max'),65535),(('usb','frame_kind'),17),(('usb','ordinary_credit'),False),(('acceptance','executed_runtime_scenarios'),46)]
    for path,value in mutations:
        bad=copy.deepcopy(c); target=bad
        for part in path[:-1]:
            target=target[part]
        target[path[-1]]=value
        check(bool(contract_errors(bad)), 'mutation:'+'.'.join(path))
    return {'scope':'design-lint-and-serialization-only','passed':not issues,'errors':issues,'checks':len(checks),'documents':len(markdown),'local_links':links,'negative_manifest_mutations':len(mutations),'planned_runtime_cases':46,'executed_runtime_cases':0,'hardware_tested':False,'signature_validation_tested':False}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    try:
        report=run(args.root.resolve())
    except (OSError,ValueError,KeyError,TypeError,struct.error) as exc:
        report={'scope':'design-lint-and-serialization-only','passed':False,'errors':[str(exc)]}
    text=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    print(text,end='')
    if args.report:
        args.report.write_text(text,encoding='utf-8')
    return 0 if report['passed'] else 1

if __name__=='__main__':
    raise SystemExit(main())
