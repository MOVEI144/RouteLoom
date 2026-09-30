"""Cold-start convergence: all-board reset (daemon stopped), restart daemon, time routes, then 10 sends each."""
import sys, json, subprocess, time, pathlib, datetime
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel, reps = sys.argv[1], int(sys.argv[2])
nodes = [int(x) for x in sys.argv[3].split(',')] if len(sys.argv) > 3 else [2, 3]
R = h.REPO; CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
base = h.RUN / outrel; base.mkdir(parents=True, exist_ok=True)
results = []
for rep in range(reps):
    out = base / f'rep-{rep:02d}'; out.mkdir(exist_ok=True)
    subprocess.run(['pkill', '-x', 'routeloom-host']); time.sleep(1.5)
    ra = subprocess.run([sys.executable, str(R / 'tools/hil/reset_all.py'), '--rig', str(R / 'tools/hil/rigs.yaml'),
                         '--bench', 'bench-2026-09-29-h0', '--boards', 'bridge', 'relay', 'endpoint', '--out', str(out / 'reset')],
                        capture_output=True, text=True, timeout=200)
    rec = json.loads((out / 'reset' / 'result.json').read_text())
    released = max(datetime.datetime.fromisoformat(b['released']).timestamp() for b in rec['boards'])
    log = open(out / 'daemon.log', 'w')
    d_start = time.time()
    subprocess.Popen(['/tmp/routeloom-hil-v2/h1/daemon.sh', str(out / 'daemon.log')], start_new_session=True)
    rc_start = time.time()
    subprocess.run([sys.executable, str(R / 'tools/hil/route_convergence.py'), '--ctl', CTL, '--socket', SOCK,
                    '--nodes', *map(str, nodes), '--seconds', '150', '--out', str(out / 'routes.jsonl')],
                   capture_output=True, text=True, timeout=200)
    summ = json.loads(pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json').read_text()) \
        if pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json').exists() else {}
    off = rc_start - released
    row = {'rep': rep, 'reset_release_skew_ms': rec['release_skew_ms'], 'daemon_start_after_release_s': round(d_start - released, 3),
           'auth_after_release_s': None if summ.get('authenticated_at_s') is None else round(summ['authenticated_at_s'] + off, 3),
           'routes_after_release_s': {k: round(v + off, 3) for k, v in (summ.get('routes_at_s') or {}).items()},
           'all_routes_after_release_s': None if summ.get('all_routes_at_s') is None else round(summ['all_routes_at_s'] + off, 3)}
    sends = []
    for n in nodes:
        for i in range(10):
            rep_ = json.loads(subprocess.run([CTL, '--socket', SOCK, 'send', str(n), (b'M05' + bytes([rep, n, i])).hex()],
                                             capture_output=True, text=True).stdout)
            sends.append({'node': n, 'i': i, 'reply': rep_}); time.sleep(0.5)
    time.sleep(8)
    dl = json.loads(subprocess.run([CTL, '--socket', SOCK, 'deliveries'], capture_output=True, text=True).stdout)['deliveries']
    byreq = {d['request']: d for d in dl}
    for s in sends:
        s['delivery'] = byreq.get(s['reply'].get('request'), {})
    row['after_sends'] = {str(n): sum(1 for s in sends if s['node'] == n and s['delivery'].get('state') == 'delivered') for n in nodes}
    (out / 'sends.json').write_text(json.dumps(sends, indent=1))
    results.append(row); print(json.dumps(row), flush=True)
    time.sleep(5)
(base / 'summary.json').write_text(json.dumps(results, indent=2))
print('FLOW_DONE', flush=True)
