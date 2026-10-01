"""J05 on hardware (recovery-join variant): hold the endpoint in the ROM, revoke it
(the gateway applies RRS1 and cancels the notice), release it: it must learn its
removal over the recovery join, wait out the 10-min holdoff, restart unassigned and
come back at generation 2 with the same NodeId once approved.
usage: j05.py <outrel>"""
import sys, json, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'artifacts/hil/2026-09-30-stab/scripts'))
import stablib as h
h.RUN=ROOT/'artifacts/hil/2026-10-01-stab-review'
outrel = sys.argv[1]
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-stab.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / 'j05.jsonl', 'a')


def ctl(*a, timeout=30):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=timeout)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {'raw': r.stdout[-300:], 'err': r.stderr[-300:]}


def rec(step, **k):
    k['step'] = step; k['t'] = round(time.time(), 3)
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:400], flush=True)


def member3():
    for m in ctl('site', 'members').get('result', {}).get('members', []):
        if m['device_id'] == '0000000000000003':
            return m
    return {}


rec('before', member=member3())
h.preflight('endpoint',out)
h.hold_rom('endpoint')
held_at=time.monotonic()
rec('endpoint_held')
r = ctl('site', 'revoke', '--device', '0000000000000003', '--expected-generation', '1',
        '--reason', 'removed', '--idempotency-key', f'stab-j05-{int(time.time())}')
rec('revoke', reply=r)
time.sleep(max(0,held_at+8-time.monotonic()))
h.hard_reset('endpoint')
time.sleep(2)
cap = subprocess.Popen([sys.executable, str(Path(__file__).parent/'capture.py'), 'endpoint', '1500',
                        str(out / 'console-endpoint.log')], start_new_session=True)
appr = subprocess.Popen([sys.executable, str(h.REPO / 'tools/hil/join_approve.py'), '--socket', SOCK,
                         '--device-id', '0000000000000003', '--role', 'endpoint', '--timeout-s', '1450'],
                        stdout=open(out / 'approve.out', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
t_rel = time.monotonic()
rec('endpoint_released', isolation_s=round(time.monotonic()-held_at,3), member=member3())
while time.monotonic() - t_rel < 1440:
    m = member3()
    if m.get('state') == 'member' and m.get('generation') == 2 and m.get('confirm_state') == 'active':
        break
    time.sleep(5)
rec('rejoined', after_release_s=round(time.monotonic() - t_rel, 1), member=m)
assert m.get('state') == 'member' and m.get('generation') == 2 and m.get('confirm_state') == 'active', 'generation 2 did not return'
res = []
for i in range(10):
    s = ctl('send', '3', (b'J05' + bytes([i])).hex())
    res.append(s); time.sleep(1.5)
time.sleep(8)
dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
states = [dl.get(s.get('request'), {}).get('state') for s in res]
rec('sends', delivered=sum(1 for s in states if s == 'delivered'), states=states)
cap.terminate()
appr.terminate()
print('FLOW_DONE', flush=True)
