"""Reboot only the gateway after a failed cutover; retain the plan and credentials."""
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import serial

root = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('stablib', root / 'artifacts/hil/2026-09-30-stab/scripts/stablib.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
out = root / 'artifacts/hil/2026-10-01-stab/channel-1-gateway-reboot'
out.mkdir(parents=True, exist_ok=True)
base = [h.CTL, '--socket', '/tmp/routeloom-hil-v2-stab.sock']

def ctl(*args):
    p = subprocess.run(base + list(args), capture_output=True, text=True, timeout=15)
    return json.loads(p.stdout) if p.stdout else {'error': p.stderr}

record = {'before': ctl('adapter'), 'utc': h.stamp()}
boot = record['before']['session']['boot']
_, port = h.board('bridge')
s = serial.Serial(port=None, baudrate=115200, timeout=.1)
s.dtr = False; s.rts = False; s.port = port; s.open()
s.rts = True; time.sleep(.2); s.rts = False; s.close()
start = time.monotonic()
while time.monotonic() - start < 60:
    a = ctl('adapter')
    if a.get('session', {}).get('authenticated') and a['session']['boot'] != boot:
        break
    time.sleep(.25)
record['reauth_s'] = time.monotonic() - start
while time.monotonic() - start < 90:
    nodes = ctl('nodes').get('result', {}).get('nodes', [])
    if {2, 3} <= {int(n['node'], 16) for n in nodes if n.get('connected')}:
        break
    time.sleep(1)
record['routes_s'] = time.monotonic() - start
record['nodes'] = nodes
record['sends'] = []
for node in (2, 3):
    for i in range(20):
        record['sends'].append({'node': node, 'reply': ctl('send', str(node), bytes([node, i]).hex())})
        time.sleep(.8)
time.sleep(8)
d = {r['request']: r for r in ctl('deliveries').get('deliveries', [])}
for row in record['sends']:
    row['delivery'] = d.get(row['reply'].get('request'), {})
record['delivered'] = {str(n): sum(r['node'] == n and r['delivery'].get('state') == 'delivered' for r in record['sends']) for n in (2, 3)}
(out / 'result.json').write_text(json.dumps(record, indent=2))
print(json.dumps({k: record[k] for k in ('reauth_s', 'routes_s', 'delivered')}), flush=True)
