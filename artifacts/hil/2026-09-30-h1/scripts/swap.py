"""App-only swap of the field image on boards, NVS hashes checked. usage: swap.py <outrel> board=bundle ..."""
import sys, json, time
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel = sys.argv[1]
res = {}
for spec in sys.argv[2:]:
    name, bundle = spec.split('=')
    out = h.RUN / outrel / name
    out.mkdir(parents=True, exist_ok=True)
    for attempt in range(3):
        try:
            before = h.nvs_dump(name, f'{outrel.replace("/","_")}-before')
            ao = h.app_only(name, h.REPO / 'artifacts/hil/images' / bundle, out)
            after = h.nvs_dump(name, f'{outrel.replace("/","_")}-after')
            break
        except Exception as exc:
            print(name, 'attempt', attempt, 'failed', str(exc)[:200], flush=True)
            time.sleep(5)
    else:
        raise SystemExit(f'{name} swap failed')
    res[name] = {'bundle': bundle, 'app_sha256': ao['app_sha256'], 'app_bytes': ao['app_bytes'],
                 'nvs_preserved': {k: before[k]['sha256'] == after[k]['sha256'] for k in ('rlcfg', 'rlkeys', 'rlsec')}}
    print(name, json.dumps(res[name]), flush=True)
(h.RUN / outrel / 'swap.json').write_text(json.dumps(res, indent=2))
print('FLOW_DONE')
