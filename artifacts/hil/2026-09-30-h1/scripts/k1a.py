"""K1a / M04 on hardware: stop the gateway (ROM download mode, radio off) for N s, restore, time link/routes,
10+10 sends, then a follow-up of 100 sends. Relay/endpoint consoles captured throughout (reboot check).
usage: k1a.py <outrel> <stop_s> <follow_count> <follow_pace_s>"""
import sys, json, subprocess, time, pathlib, datetime
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel, stop_s, fcount, fpace = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
R = h.REPO; CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
ev = open(out / 'events.jsonl', 'a')


def note(**k):
    k['t'] = time.time(); k['iso'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
    ev.write(json.dumps(k) + '\n'); ev.flush(); print(json.dumps(k), flush=True)


def ctl(*a):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=30)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {'raw': r.stdout[-300:], 'err': r.stderr[-300:]}


b, port = h.board('bridge')
total = stop_s + 600 + fcount * float(fpace) + 300
caps = [subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/cap.py', n, str(total), str(out / f'console-{n}.log')],
                         start_new_session=True) for n in ('relay', 'endpoint')]
time.sleep(3)
(out / 'routes-before.json').write_text(json.dumps(ctl('topology', '--observer', '0000000000000001', '--section', 'routes')))
subprocess.run(['pkill', '-x', 'routeloom-host']); time.sleep(1)
r = subprocess.run([h.ESPTOOL, '--chip', b.chip, '--port', port, '--after', 'no-reset', 'chip-id'], capture_output=True, text=True, timeout=60)
(out / 'stop-esptool.log').write_text(r.stdout + r.stderr)
t_stop = time.time(); note(event='gateway_stopped', rc=r.returncode, how='ROM download mode (esptool --after no-reset), radio off')
while time.time() - t_stop < stop_s:
    time.sleep(10)
r = subprocess.run([h.ESPTOOL, '--chip', b.chip, '--port', port, '--after', 'hard-reset', 'chip-id'], capture_output=True, text=True, timeout=60)
(out / 'restore-esptool.log').write_text(r.stdout + r.stderr)
t_rest = time.time(); note(event='gateway_restored', stopped_s=round(t_rest - t_stop, 1), rc=r.returncode)
subprocess.Popen(['/tmp/routeloom-hil-v2/h1/daemon.sh', str(out / 'daemon.log')], start_new_session=True)
t_rc = time.time()
subprocess.run([sys.executable, str(R / 'tools/hil/route_convergence.py'), '--ctl', CTL, '--socket', SOCK,
                '--nodes', '2', '3', '--seconds', '180', '--out', str(out / 'routes.jsonl')], capture_output=True, text=True, timeout=240)
p = pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json')
summ = json.loads(p.read_text()) if p.exists() else {}
off = t_rc - t_rest
note(event='converged', auth_after_restore_s=None if summ.get('authenticated_at_s') is None else round(summ['authenticated_at_s'] + off, 2),
     routes_after_restore_s={k: round(v + off, 2) for k, v in (summ.get('routes_at_s') or {}).items()},
     all_routes_after_restore_s=None if summ.get('all_routes_at_s') is None else round(summ['all_routes_at_s'] + off, 2))
(out / 'neighbors-after.json').write_text(json.dumps(ctl('topology', '--observer', '0000000000000001', '--section', 'neighbors')))
sends = []
for n in (3, 2):
    for i in range(10):
        rep = ctl('send', str(n), (b'K1A' + bytes([n, i])).hex())
        sends.append({'node': n, 'i': i, 'reply': rep, 't': time.time()}); time.sleep(1.0)
time.sleep(8)
dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
for s in sends:
    s['delivery'] = dl.get(s['reply'].get('request'), {})
(out / 'sends-after.json').write_text(json.dumps(sends, indent=1))
note(event='sends_after_restore', delivered={str(n): sum(1 for s in sends if s['node'] == n and s['delivery'].get('state') == 'delivered') for n in (3, 2)},
     first_send_after_restore_s=round(sends[0]['t'] - t_rest, 1))
tr = subprocess.run([sys.executable, str(R / 'tools/hil/accepted_traffic.py'), '--ctl', CTL, '--socket', SOCK,
                     '--destinations', '3', '--count', str(fcount), '--timeout-s', str(fcount * float(fpace) + 300), '--pace-s', fpace,
                     '--out', str(out / 'follow.jsonl')], capture_output=True, text=True, timeout=fcount * float(fpace) + 400)
(out / 'follow.out').write_text(tr.stdout + tr.stderr)
rows = [json.loads(l) for l in open(out / 'follow.jsonl')] if (out / 'follow.jsonl').exists() else []
states = {}
for r_ in rows:
    st = r_.get('delivery', {}).get('state'); states[st] = states.get(st, 0) + 1
note(event='follow_done', states=states, accepted=len(rows))
(out / 'routes-end.json').write_text(json.dumps(ctl('topology', '--observer', '0000000000000001', '--section', 'routes')))
for c in caps:
    c.terminate()
print('FLOW_DONE', flush=True)
