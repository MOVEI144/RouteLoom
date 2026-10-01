"""App-only bridge image swap with preserved NVS and fresh USB authentication."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('stablib', root / 'artifacts/hil/2026-09-30-stab/scripts/stablib.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
label, relative = sys.argv[1:]
out = root / 'artifacts/hil/2026-10-01-stab' / relative
out.mkdir(parents=True, exist_ok=True)
sock = '/tmp/routeloom-hil-v2-stab.sock'
for p in Path('/proc').iterdir():
    if not p.name.isdecimal(): continue
    try: args = (p / 'cmdline').read_bytes().decode(errors='replace').split('\0')
    except (FileNotFoundError, PermissionError, ProcessLookupError): continue
    if args[0].endswith('/routeloom-host') and sock in args:
        try: os.kill(int(p.name), signal.SIGTERM)
        except ProcessLookupError: pass
time.sleep(1)
before = h.nvs_dump('bridge', relative + '-before')
bundle = root / 'artifacts/hil/images' / label
source_sha = json.loads((bundle / 'manifest.json').read_text())['sdk_commit']
f = h.app_only('bridge', bundle, out)
after = h.nvs_dump('bridge', relative + '-after')
t0 = time.monotonic(); h.hard_reset('bridge')
site = Path('/tmp/routeloom-hil-v2/stab-review-20261001/site')
subprocess.Popen([str(root / 'host/target/debug/routeloom-host'), '--socket', sock, '--device', h.board('bridge')[1], '--api-acl-file', '/tmp/routeloom-hil-v2/h1/acl.json', '--usb-dev-secret-file', str(site / 'usb-dev-secret.key'), '--site-authority', str(site), '--admission-profile', 'bench-v1'], stdout=(out / 'daemon.log').open('w'), stderr=subprocess.STDOUT, start_new_session=True)
status = {}
while time.monotonic() - t0 < 60:
    r = subprocess.run([h.CTL, '--socket', sock, 'adapter'], capture_output=True, text=True)
    try: status = json.loads(r.stdout)
    except json.JSONDecodeError: time.sleep(.2); continue
    if status.get('session', {}).get('authenticated'): break
    time.sleep(.2)
record = {'source_sha': source_sha, 'image': label, 'app_only': f, 'nvs_before': before, 'nvs_after': after, 'nvs_preserved': before == after, 'after_reset_s': round(time.monotonic() - t0, 3), 'adapter': status}
(out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record), flush=True)
assert status.get('session', {}).get('authenticated')
