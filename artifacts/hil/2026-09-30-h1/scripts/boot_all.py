"""Reset all boards together, start the daemon and long console captures, wait for routes.
usage: boot_all.py <outrel> <capture_s>"""
import sys, json, subprocess, time, pathlib, datetime
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel, cap_s = sys.argv[1], sys.argv[2]
R = h.REPO; CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
subprocess.run(['pkill', '-x', 'routeloom-host']); time.sleep(1.5)
ra = subprocess.run([sys.executable, str(R / 'tools/hil/reset_all.py'), '--rig', str(R / 'tools/hil/rigs.yaml'),
                     '--bench', 'bench-2026-09-29-h0', '--boards', 'bridge', 'relay', 'endpoint', '--out', str(out / 'reset')],
                    capture_output=True, text=True, timeout=200)
(out / 'reset_all.out').write_text(ra.stdout + ra.stderr)
rec = json.loads((out / 'reset' / 'result.json').read_text())
released = max(datetime.datetime.fromisoformat(b['released']).timestamp() for b in rec['boards'])
subprocess.Popen(['/tmp/routeloom-hil-v2/h1/daemon.sh', str(out / 'daemon.log')], start_new_session=True)
pids = []
for n in ('relay', 'endpoint'):
    p = subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/cap.py', n, cap_s, str(out / f'console-{n}.log')], start_new_session=True)
    pids.append(p.pid)
(out / 'capture.pids').write_text(' '.join(map(str, pids)))
t_rc = time.time()
subprocess.run([sys.executable, str(R / 'tools/hil/route_convergence.py'), '--ctl', CTL, '--socket', SOCK,
                '--nodes', '2', '3', '--seconds', '120', '--out', str(out / 'routes.jsonl')], capture_output=True, text=True, timeout=200)
p = pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json')
summ = json.loads(p.read_text()) if p.exists() else {}
off = t_rc - released
row = {'auth_after_release_s': None if summ.get('authenticated_at_s') is None else round(summ['authenticated_at_s'] + off, 2),
       'routes_after_release_s': {k: round(v + off, 2) for k, v in (summ.get('routes_at_s') or {}).items()},
       'released_unix': released, 'capture_pids': pids}
(out / 'boot.json').write_text(json.dumps(row, indent=2))
print(json.dumps(row)); print('FLOW_DONE', flush=True)
