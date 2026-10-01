"""MemberEdhoc provisioning of one H0 board: erase, setup image, BoardConfig, identity, field app-only."""
import sys, json, pathlib, hashlib, subprocess, time
ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'artifacts/hil/2026-09-30-stab/scripts'))
import stablib as h
h.RUN = pathlib.Path(__file__).resolve().parents[1]
h.PRIV = pathlib.Path((ROOT / 'build-review-logs/private-site-path.txt').read_text().strip()).parent
from routeloom_meshviz import provisioning as pv

import os
SITE = h.PRIV / 'site'
SPEC = pathlib.Path(str(SITE) + '.lab-spec.json')
authority = json.loads((SITE / 'site-authority.json').read_text())
lab = json.loads(SPEC.read_text())
identity_spec = pathlib.Path(str(SITE) + '.identity-spec.json')
if not identity_spec.exists():
    identity_spec.write_text(json.dumps({
        'format': 'routeloom-identity-spec-v1', 'model': 1, 'hw_rev': 1, 'flags': 0,
        'anchors': [{'anchor_id': lab['site_ca_id'], 'kind': 'site-ca',
                     'status': 'active', 'pubkey_hex': authority['site_ca_pubkey_hex']}]}))
    identity_spec.chmod(0o600)
IMG = h.REPO / 'artifacts/hil/images'
PLAN = {'bridge': ('0000000000000001', 'bridge', 'stab-fix-setup-br', 'review-br', 401),
        'relay': ('0000000000000002', 'bench', 'stab-fix-setup-ref', 'review-relay', 402),
        'endpoint': ('0000000000000003', 'bench', 'stab-fix-setup-ref', 'review-ep', 403)}
name = sys.argv[1]
node, role, setup, field, serial = PLAN[name]
if len(sys.argv) > 2:
    field = sys.argv[2]
out = h.RUN / 'provision-member' / name
out.mkdir(parents=True, exist_ok=True)
rec = {'board': name, 'node': node, 'role': role, 'setup_bundle': setup, 'field_bundle': field}
b, port = h.board(name)
import os
if os.environ.get('RESUME_AFTER_SEAL'):
    pass
else:
  # 1. preflight + full erase (only the three H0 boards may be erased)
  ident = h.preflight(name, out)
  rec['before_factory_reset'] = h.nvs_dump(name, 'before-factory-reset')
  er = subprocess.run(['true'], capture_output=True, text=True) if os.environ.get('SKIP_FLASH') else subprocess.run([h.ESPTOOL, '--chip', b.chip, '--port', port, 'erase-flash'], capture_output=True, text=True, timeout=180)
  (out / 'erase.log').write_text(er.stdout + er.stderr)
  assert er.returncode == 0, 'erase failed'
  rec['erase'] = 'ok'
  # 2. setup image, BoardConfig (member)
  if not os.environ.get('SKIP_FLASH'):
    h.full_flash(name, h.REPO / 'build/hil-stab-fix-images' / setup, out, boot_seconds=3.0)
  for attempt in range(4):
    try:
      rec['config'] = h.commit_config(name, SITE, node, 'member-edhoc', role)
      break
    except Exception as exc:
      print('config attempt', attempt, 'failed:', str(exc)[:200], flush=True)
      rec.setdefault('config_retries', []).append(str(exc)[:200])
      time.sleep(6)
  else:
    raise SystemExit('config commit failed')
  print('config', rec['config'], flush=True)
# 3. identity: keygen / PoP / DevCert / seal / lock over the same console
office = pv.CtlOffice(h.CTL, str(SITE / 'keys/device-ca.key'), str(SITE) + '.identity-spec.json', str(SITE / 'keys/office-ledger.jsonl'))
spec = json.loads(SPEC.read_text())
plan = pv.BoardProvisionPlan(site_id=spec['site_id'], work_id=f'node-{node}-{os.environ.get("ATTEMPT", "1")}', board_uuid=h.STA_MAC[name],
                             base_mac=h.STA_MAC[name], node_id=node, serial=serial, role=role,
                             out_dir=str(SITE / 'provisioned' / node)).validate()
prov = pv.Provisioner(SITE / 'provision-journal', office)
import os
if os.environ.get('RESUME_AFTER_SEAL'):
    rec['identity_error'] = 'resumed after a console panic; identity sealed per setup boot log'
else:
    link = h.console_link(name)
    try:
        journal = prov.run(plan, link)
        rec['identity_status'] = link.exchange('status')[:200]
    except Exception as exc:
        rec['identity_error'] = str(exc)[:300]
    finally:
        link.close()
print('identity', rec.get('identity_status'), rec.get('identity_error'), flush=True)
rec['nvs_after_identity'] = h.nvs_dump(name, 'member-after-identity')
# 4. field image app-only; NVS preserved
rec['app_only'] = h.app_only(name, IMG / field, out)
rec['nvs_after_app_write'] = h.nvs_dump(name, 'member-after-app-write')
rec['nvs_preserved'] = {k: rec['nvs_after_identity'][k]['sha256'] == rec['nvs_after_app_write'][k]['sha256']
                        for k in ('rlcfg', 'rlkeys', 'rlsec')}
h.hard_reset(name)
if name not in ('bridge', 'swap-bridge'):
    time.sleep(2.0)
    lines = h.boot_capture(name, 15, out / f'field-boot-{name}.log', reset=True)
    try:
        desc = pv.app_image_descriptor(IMG / field / 'images/application.bin')
        j = prov.finalize(plan, boot_log=lines, expected_app_sha256=desc['app_elf_sha256'])
        rec['readback'] = j.latest('readback')
    except Exception as exc:  # evidence only
        rec['readback_error'] = str(exc)
if rec.get('identity_error') or rec.get('readback_error'):
    raise RuntimeError('provisioning or readback did not complete')
(out / 'provision.json').write_text(json.dumps(rec, indent=2))
print(json.dumps({k: rec.get(k) for k in ('nvs_preserved', 'readback', 'readback_error')}))
