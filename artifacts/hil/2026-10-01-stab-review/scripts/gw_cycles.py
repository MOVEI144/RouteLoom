"""M06 gateway reset with the daemon running: per cycle pulse the C3 EN line through
its USB Serial/JTAG port (the daemon keeps the port open), send two probes during the
USB outage (must end terminal or be refused), wait for the new authenticated session,
then send N at a gap to Node <dst> and record every terminal state.
usage: gw_cycles.py <outrel> <dst> <cycles> <sends> <gap_s>"""
import sys, json, subprocess, time, serial
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'artifacts/hil/2026-09-30-stab/scripts'))
import stablib as h
h.RUN=ROOT/'artifacts/hil/2026-10-01-stab-review'
outrel, dst, cycles, n, gap = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-stab.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / 'cycles.jsonl', 'a')
TERMINAL = {'delivered', 'expired', 'failed', 'rejected', 'cancelled', 'indeterminate'}


def ctl(*a, timeout=15):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=timeout)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {'raw': r.stdout[-300:], 'err': r.stderr[-300:]}


def rec(**k):
    k['t'] = round(time.time(), 3)
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:200].replace('\n',' '), flush=True)


def session():
    a = ctl('adapter')
    s = a.get('session', {}) if isinstance(a, dict) else {}
    return bool(s.get('authenticated')), s.get('boot'), a


def pulse():
    b, port = h.board('bridge')
    s = serial.Serial(port=None, baudrate=115200, timeout=0.1, exclusive=False)
    s.port = port
    s.dtr = False; s.rts = False
    s.open()
    s.dtr = False; s.rts = True; time.sleep(0.2); s.rts = False
    s.close()


def send(tag):
    r = ctl('send', str(dst), tag.encode().hex())
    return {'tag': tag, 'reply': r, 'admitted': time.monotonic()}


def settle(rows, limit=30):
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
        done = True
        for r in rows:
            req = r['reply'].get('request')
            d = dl.get(req) if req is not None else None
            r['delivery'] = d or {}
            if d and d.get('state') in TERMINAL and 'finished_mono' not in r:
                r['finished_mono'] = time.monotonic()
            if req is not None and (d is None or d.get('state') not in TERMINAL):
                done = False
        if done:
            return
        time.sleep(.05)


ok0, boot0, a0 = session()
rec(step='start', authenticated=ok0, adapter=a0)
total = 0
for c in range(cycles):
    t_reset = time.monotonic()
    pulse()
    rec(step='reset', cycle=c)
    probes = [send(f'gwc{c}-probe{i}') for i in range(2)]
    t_auth = None
    while time.monotonic() - t_reset < 60:
        ok, boot, a = session()
        if ok and time.monotonic() - t_reset > 1.0 and boot != boot0:
            t_auth = time.monotonic(); boot0 = boot
            break
        time.sleep(0.25)
    rec(step='reauth', cycle=c, after_reset_s=None if t_auth is None else round(t_auth - t_reset, 2), adapter=a)
    rows = []
    view = []
    for i in range(n):
        rows.append(send(f'gwc{c}-{i}'))
        g = ctl('node-get', '--node', f'{dst:016x}').get('result', {}).get('node', {})
        view.append((round(time.monotonic() - t_reset, 1), g.get('connected'), g.get('neighbor'), g.get('next_hop'),
                     g.get('link_state') or g.get('phase')))
        # Observe terminal completions during the pacing gap too.
        until = time.monotonic() + gap
        while time.monotonic() < until:
            settle(rows + probes, limit=.1)
            time.sleep(min(.1,max(0,until-time.monotonic())))
    settle(rows + probes)
    got = sum(1 for r in rows if r['delivery'].get('state') == 'delivered')
    total += got
    rec(step='cycle', cycle=c, delivered=got, sends=n,
        states=[(r['delivery'].get('state'), r['delivery'].get('reason')) if r['reply'].get('request') is not None
                else ('refused', str(r['reply'].get('error'))[:80]) for r in rows],
        probes=[(p['delivery'].get('state'), p['delivery'].get('reason')) if p['reply'].get('request') is not None
                else ('refused', str(p['reply'].get('error'))[:80]) for p in probes],
        gateway_view=view, records=rows, probe_records=probes,
        first_delivered_after_reset_s=next((round(r['finished_mono'] - t_reset, 2) for r in rows
                                            if r['delivery'].get('state') == 'delivered'), None))
log.close()
rec_log = (out / 'rows.json').open('w')
rec_log.write(json.dumps({'last_cycle_rows':rows,'last_cycle_probes':probes},indent=2));rec_log.close()
log = (out / 'cycles.jsonl').open('a')
rec(step='done', delivered=total, sends=cycles * n)
print('FLOW_DONE', flush=True)
