"""All boards reset together (daemon stopped), daemon+approver started, time joins and routes."""
import sys, json, subprocess, time, pathlib, datetime, os
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel = sys.argv[1]; limit = float(sys.argv[2]) if len(sys.argv) > 2 else 300
R = h.REPO; CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
subprocess.run(['pkill', '-x', 'routeloom-host']); subprocess.run(['pkill', '-f', 'h1/cap.py']); subprocess.run(['pkill', '-f', 'h1/approve_loop.py']); time.sleep(1.5)
ra = subprocess.run([sys.executable, str(R / 'tools/hil/reset_all.py'), '--rig', str(R / 'tools/hil/rigs.yaml'),
                     '--bench', 'bench-2026-09-29-h0', '--boards', 'bridge', 'relay', 'endpoint', '--out', str(out / 'reset')],
                    capture_output=True, text=True, timeout=200)
(out / 'reset_all.out').write_text(ra.stdout + ra.stderr)
rec = json.loads((out / 'reset' / 'result.json').read_text())
released = max(datetime.datetime.fromisoformat(b['released']).timestamp() for b in rec['boards'])
procs = [subprocess.Popen(['/tmp/routeloom-hil-v2/h1/daemon.sh', str(out / 'daemon.log')], start_new_session=True)]
t_daemon = time.time()
for n in ('relay', 'endpoint'):
    procs.append(subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/cap.py', n, str(limit + 60), str(out / f'console-{n}.log')], start_new_session=True))
procs.append(subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/approve_loop.py', SOCK, str(limit + 30), str(out / 'approvals.jsonl')], start_new_session=True))
rc = subprocess.Popen([sys.executable, str(R / 'tools/hil/route_convergence.py'), '--ctl', CTL, '--socket', SOCK,
                       '--nodes', '2', '3', '--seconds', str(limit), '--out', str(out / 'routes.jsonl')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
t_rc = time.time()
first_active = {}
mlog = open(out / 'members.jsonl', 'w')
while time.time() - released < limit:
    r = subprocess.run([CTL, '--socket', SOCK, 'site', 'members'], capture_output=True, text=True)
    try:
        j = json.loads(r.stdout)
    except Exception:
        j = {'raw': r.stdout[-300:], 'err': r.stderr[-300:]}
    mlog.write(json.dumps({'t': round(time.time() - released, 2), 'r': j}) + '\n'); mlog.flush()
    for m in (j.get('result', j).get('members', []) if isinstance(j, dict) else []):
        dev = str(m.get('device_id', m.get('device', ''))).lower().removeprefix('0x').zfill(16)
        if str(m.get('state', m.get('status', ''))).lower() in ('active', 'member') and dev not in first_active:
            first_active[dev] = round(time.time() - released, 2)
    if len(first_active) >= 3 and rc.poll() is not None:
        break
    time.sleep(2)
rc.wait(timeout=limit + 30)
p = pathlib.Path(str(out / 'routes.jsonl')).with_suffix('.summary.json')
summ = json.loads(p.read_text()) if p.exists() else {}
off = t_rc - released
row = {'daemon_start_after_release_s': round(t_daemon - released, 2), 'reset_release_skew_ms': rec.get('release_skew_ms'),
       'member_active_after_release_s': first_active,
       'auth_after_release_s': None if summ.get('authenticated_at_s') is None else round(summ['authenticated_at_s'] + off, 2),
       'routes_after_release_s': {k: round(v + off, 2) for k, v in (summ.get('routes_at_s') or {}).items()},
       'all_routes_after_release_s': None if summ.get('all_routes_at_s') is None else round(summ['all_routes_at_s'] + off, 2)}
(out / 'summary.json').write_text(json.dumps(row, indent=2))
print(json.dumps(row)); print('FLOW_DONE', flush=True)
