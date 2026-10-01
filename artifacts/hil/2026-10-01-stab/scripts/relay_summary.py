"""Use observed completion offsets, not reset_cycles.py's admission-time recovery."""
import datetime
import json
from pathlib import Path
import re
import sys
p = Path(sys.argv[1])
r = json.loads((p / 'result.json').read_text())
lines = (p / 'console.log').read_text(errors='replace').splitlines()
cycles = []
for c in r['cycle_results']:
    end = c['released_unix'] + max(s['offset_s'] for s in c['sends'])
    bound = {}
    for line in lines:
        m = re.match(r'\[([^]]+)\].*discovery event=BOUND peer=(\d+)', line)
        if m:
            t = datetime.datetime.fromisoformat(m[1]).timestamp()
            if c['released_unix'] <= t <= end:
                bound.setdefault(m[2], round(t - c['released_unix'], 3))
    delivered = [s for s in c['sends'] if s.get('delivery', {}).get('state') == 'delivered']
    cycles.append({'cycle': c['cycle'], 'delivered': len(delivered),
                   'first_delivery_s': delivered[0]['offset_s'] if delivered else None,
                   'bound_s': bound})
s = {'cycles': cycles, 'delivered': sum(c['delivered'] for c in cycles),
     'note': 'BOUND times use timestamped console observations; delivery offsets use the monotonic clock.'}
(p / 'acceptance.json').write_text(json.dumps(s, indent=2) + '\n')
print(json.dumps(s))
