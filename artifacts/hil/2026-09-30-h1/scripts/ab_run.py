"""A/B campaign: all-board reset, cold-start routes, bridge heap, 100 host->Node3 sends over the forced 2 hop.
usage: ab_run.py <outrel> [count] [pace]"""
import sys, json, subprocess, time, pathlib, datetime, statistics
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 100
pace = sys.argv[3] if len(sys.argv) > 3 else '2'
R = h.REPO; CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)


def ctl(*a):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=30)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {'raw': r.stdout[-400:], 'err': r.stderr[-400:]}


subprocess.run(['pkill', '-x', 'routeloom-host']); time.sleep(1.5)
ra = subprocess.run([sys.executable, str(R / 'tools/hil/reset_all.py'), '--rig', str(R / 'tools/hil/rigs.yaml'),
                     '--bench', 'bench-2026-09-29-h0', '--boards', 'bridge', 'relay', 'endpoint', '--out', str(out / 'reset')],
                    capture_output=True, text=True, timeout=200)
(out / 'reset_all.out').write_text(ra.stdout + ra.stderr)
rec = json.loads((out / 'reset' / 'result.json').read_text())
released = max(datetime.datetime.fromisoformat(b['released']).timestamp() for b in rec['boards'])
kids = [subprocess.Popen(['/tmp/routeloom-hil-v2/h1/daemon.sh', str(out / 'daemon.log')], start_new_session=True)]
t_daemon = time.time()
caps = [subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/cap.py', n, '1500', str(out / f'console-{n}.log')],
                         start_new_session=True) for n in ('relay', 'endpoint')]
t_rc = time.time()
subprocess.run([sys.executable, str(R / 'tools/hil/route_convergence.py'), '--ctl', CTL, '--socket', SOCK,
                '--nodes', '2', '3', '--seconds', '150', '--out', str(out / 'routes.jsonl')],
               capture_output=True, text=True, timeout=200)
p = pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json')
summ = json.loads(p.read_text()) if p.exists() else {}
off = t_rc - released
row = {'daemon_start_after_release_s': round(t_daemon - released, 2), 'reset_release_skew_ms': rec.get('release_skew_ms'),
       'auth_after_release_s': None if summ.get('authenticated_at_s') is None else round(summ['authenticated_at_s'] + off, 2),
       'routes_after_release_s': {k: round(v + off, 2) for k, v in (summ.get('routes_at_s') or {}).items()},
       'all_routes_after_release_s': None if summ.get('all_routes_at_s') is None else round(summ['all_routes_at_s'] + off, 2)}
heap = []
for i in range(3):
    j = ctl('health', '--observer', '0000000000000001', '--section', 'system')
    try:
        s = j['result']['snapshot']['system']
        heap.append({'uptime_ms': s['uptime_ms'], **s['heap']})
    except Exception:
        heap.append({'error': str(j)[:300]})
    time.sleep(5)
row['bridge_heap_after_boot'] = heap
(out / 'topology-before.json').write_text(json.dumps(ctl('topology', '--observer', '0000000000000001', '--section', 'routes')))
tr = subprocess.run([sys.executable, str(R / 'tools/hil/accepted_traffic.py'), '--ctl', CTL, '--socket', SOCK,
                     '--destinations', '3', '--count', str(count), '--timeout-s', str(count * float(pace) + 300), '--pace-s', pace,
                     '--out', str(out / 'traffic.jsonl')], capture_output=True, text=True, timeout=count * float(pace) + 400)
(out / 'traffic.out').write_text(tr.stdout + tr.stderr)
(out / 'topology-after.json').write_text(json.dumps(ctl('topology', '--observer', '0000000000000001', '--section', 'routes')))
j = ctl('health', '--observer', '0000000000000001', '--section', 'system')
try:
    s = j['result']['snapshot']['system']
    row['bridge_heap_after_traffic'] = {'uptime_ms': s['uptime_ms'], **s['heap']}
except Exception:
    row['bridge_heap_after_traffic'] = {'error': str(j)[:300]}
rows = [json.loads(l) for l in open(out / 'traffic.jsonl')] if (out / 'traffic.jsonl').exists() else []
lat = sorted(r['latency_ms'] for r in rows if r.get('delivery', {}).get('state') == 'delivered' and 'latency_ms' in r)


def pct(v, q):
    if not v:
        return None
    k = max(0, min(len(v) - 1, int(round(q * (len(v) - 1)))))
    return v[k]


states = {}
for r in rows:
    st = r.get('delivery', {}).get('state')
    states[st] = states.get(st, 0) + 1
row['traffic'] = {'accepted': len(rows), 'states': states, 'delivered': len(lat),
                  'p50_ms': pct(lat, 0.5), 'p95_ms': pct(lat, 0.95), 'p99_ms': pct(lat, 0.99), 'max_ms': lat[-1] if lat else None,
                  'mean_ms': round(statistics.mean(lat), 1) if lat else None}
time.sleep(12)  # one more owner-stats log period on the consoles
for c in caps:
    c.terminate()
cr = subprocess.run([sys.executable, str(R / 'tools/hil/correlate_receipts.py'), '--traffic', str(out / 'traffic.jsonl'),
                     '--console', str(out / 'console-endpoint.log'), '--out', str(out / 'receipts-endpoint.json')],
                    capture_output=True, text=True)
(out / 'correlate.out').write_text(cr.stdout + cr.stderr)
(out / 'summary.json').write_text(json.dumps(row, indent=2))
print(json.dumps(row)); print('FLOW_DONE', flush=True)
