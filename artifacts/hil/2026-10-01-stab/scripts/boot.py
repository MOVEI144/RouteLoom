"""Common reset and convergence on the isolated fresh acceptance site."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import os
import signal

root = Path(__file__).resolve().parents[4]
previous = root / 'artifacts/hil/2026-09-30-stab/scripts'
spec = importlib.util.spec_from_file_location('stablib', previous / 'stablib.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
out = root / 'artifacts/hil/2026-10-01-stab' / sys.argv[1]
out.mkdir(parents=True, exist_ok=True)
site = Path('/tmp/routeloom-hil-v2/stab-review-20261001/site')
sock = '/tmp/routeloom-hil-v2-stab.sock'
for proc in Path('/proc').iterdir():
    if not proc.name.isdecimal():
        continue
    try:
        args = (proc / 'cmdline').read_bytes().decode(errors='replace').split('\0')
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    command = ' '.join(args)
    ours = (args[0].endswith('/routeloom-host') and sock in args) or (
        'python' in args[0] and ('join_approve.py' in command and sock in args or
        'cap.py' in command and str(root / 'artifacts/hil/2026-10-01-stab') in command))
    if ours:
        try:
            os.kill(int(proc.name), signal.SIGTERM)
        except ProcessLookupError:
            pass
time.sleep(.5)
reset = subprocess.run([sys.executable, str(root / 'tools/hil/reset_all.py'), '--rig', str(root / 'tools/hil/rigs.yaml'), '--bench', 'bench-2026-09-29-h0', '--boards', 'bridge', 'relay', 'endpoint', '--out', str(out / 'reset')], capture_output=True, text=True)
(out / 'reset.out').write_text(reset.stdout + reset.stderr)
assert reset.returncode == 0
log = (out / 'daemon.log').open('w')
subprocess.Popen([str(root / 'host/target/debug/routeloom-host'), '--socket', sock, '--device', h.board('bridge')[1], '--api-acl-file', '/tmp/routeloom-hil-v2/h1/acl.json', '--usb-dev-secret-file', str(site / 'usb-dev-secret.key'), '--site-authority', str(site), '--admission-profile', 'bench-v1'], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
time.sleep(2)
for node, role in ((1, 'gateway'), (2, 'relay'), (3, 'endpoint')):
    subprocess.Popen([sys.executable, str(root / 'tools/hil/join_approve.py'), '--socket', sock, '--device-id', f'{node:016x}', '--role', role, '--timeout-s', '120'], stdout=(out / f'approve-{node}.jsonl').open('w'), stderr=subprocess.STDOUT, start_new_session=True)
pids = []
for name in ('relay', 'endpoint'):
    p = subprocess.Popen([sys.executable, str(Path(__file__).parent / 'run.py'), 'cap.py', name, '150', str(out / f'console-{name}.log')], start_new_session=True)
    pids.append(p.pid)
(out / 'capture.pids').write_text(' '.join(map(str, pids)))
route_started = time.time()
r = subprocess.run([sys.executable, str(root / 'tools/hil/route_convergence.py'), '--ctl', h.CTL, '--socket', sock, '--nodes', '2', '3', '--seconds', '120', '--out', str(out / 'routes.jsonl')], capture_output=True, text=True)
(out / 'routes.out').write_text(r.stdout + r.stderr)
record = json.loads((out / 'reset/result.json').read_text())
import datetime
released = max(datetime.datetime.fromisoformat(b['released']).timestamp() for b in record['boards'])
summary = json.loads((out / 'routes.summary.json').read_text())
summary['offset_after_release_s'] = route_started - released
(out / 'boot.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary), flush=True)
