"""J05 on hardware while the endpoint is off the site's channel: revoke it, move the
site 1 -> 6 (required set is the relay only once the endpoint is removed), and let the
endpoint find the site, learn its removal over the recovery join, wait out the holdoff
and come back at generation 2 once approved.
usage: j05b.py <outrel>"""
import sys, json, subprocess, time
sys.path.insert(0, '/tmp/routeloom-hil-v2/stab')
import stablib as h
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


def report():
    ctl('site', 'channel-plan', 'status'); time.sleep(1.2)
    return ctl('site', 'channel-plan', 'status').get('result', {})


caps = [subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/stab/cap.py', n, '2000',
                          str(out / f'console-{n}.log')], start_new_session=True) for n in ('relay', 'endpoint')]
appr = subprocess.Popen([sys.executable, str(h.REPO / 'tools/hil/join_approve.py'), '--socket', SOCK,
                         '--device-id', '0000000000000003', '--role', 'endpoint', '--timeout-s', '1900'],
                        stdout=open(out / 'approve.out', 'w'), stderr=subprocess.STDOUT, start_new_session=True)
rec('before', member=member3(), plan=report())
r = ctl('site', 'revoke', '--device', '0000000000000003', '--expected-generation', '1',
        '--reason', 'removed', '--idempotency-key', f'stab-j05-{int(time.time())}')
t_rev = time.time()
rec('revoke', reply=r)
time.sleep(10)
rec('after_revoke', member=member3(), plan=report())
o = ctl('site', 'channel-plan', 'offer', '--new-channel', '6')
rec('offer', reply=o)
for _ in range(60):
    s = report(); rep = s.get('report') or {}
    if rep.get('ready', 0) >= s.get('required', 9):
        break
    time.sleep(1)
rel = ctl('site', 'channel-plan', 'release')
rec('release', reply=rel, status=s)
t0 = time.time()
while time.time() - t0 < 90:
    rep = report().get('report') or {}
    if rep.get('active_channel') == 6:
        break
    time.sleep(2)
rec('site_on_6', report=rep)
while time.time() - t_rev < 1800:
    m = member3()
    if m.get('state') == 'member' and m.get('generation') == 2 and m.get('confirm_state') == 'active':
        break
    time.sleep(5)
rec('rejoined', after_revoke_s=round(time.time() - t_rev, 1), member=m)
t1 = time.time()
while time.time() - t1 < 120:
    j = ctl('nodes')
    n3 = {n['node']: n for n in j.get('result', {}).get('nodes', [])}.get('0000000000000003', {})
    if n3.get('connected') and n3.get('next_hop'):
        break
    time.sleep(2)
res = []
for i in range(10):
    res.append(ctl('send', '3', (b'J05' + bytes([i])).hex())); time.sleep(1.5)
time.sleep(8)
dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
states = [dl.get(s.get('request'), {}).get('state') for s in res]
rec('sends', delivered=sum(1 for s in states if s == 'delivered'), states=states)
for c in caps:
    c.terminate()
print('FLOW_DONE', flush=True)
