"""Restore a working channel-6 bench through authorised fresh-site provisioning.
Never overwrite saved sealed NVS with an older snapshot or bypass plan READY.
"""
import importlib.util,json,os,subprocess,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'tools/meshviz/src'))
from routeloom_meshviz.site_supervisor import write_lab_spec,lab_site_init
parent=Path(tempfile.mkdtemp(prefix='stab-review-restored-',dir='/tmp/routeloom-hil-v2'));parent.chmod(0o700)
site=parent/'site';spec=write_lab_spec(Path(str(site)+'.lab-spec.json'),gateway='0000000000000001',channel=6)
r=lab_site_init(str(root/'host/target/debug/routeloomctl'),spec,site)
assert r['state']=='created',r
out=root/'artifacts/hil/2026-10-01-stab-review/restored-home';out.mkdir(parents=True,exist_ok=True)
(out/'site-spec.json').write_bytes(spec.read_bytes())
(root/'build-review-logs/private-site-path.txt').write_text(str(site))
# Keep the earlier public provisioning records intact; use the same recipe in
# this separate result directory and a distinct work id for each fresh key.
original=(Path(__file__).parent/'provision.py').read_text()
copy=root/'build-review-logs/restore-provision.py'
copy.write_text(original.replace('ROOT = pathlib.Path(__file__).resolve().parents[4]',f'ROOT = pathlib.Path({str(root)!r})').replace('h.RUN = pathlib.Path(__file__).resolve().parents[1]',f'h.RUN = pathlib.Path({str(out)!r})'))
env=dict(os.environ,ATTEMPT='restore-home')
for role in ('bridge','relay','endpoint'):
 subprocess.run([sys.executable,str(copy),role],check=True,env=env)
subprocess.run([sys.executable,str(Path(__file__).parent/'boot_fresh.py'),'restored-home-boot'],check=True)
subprocess.run([sys.executable,str(root/'tools/hil/accepted_traffic.py'),'--ctl',str(root/'host/target/debug/routeloomctl'),'--socket','/tmp/routeloom-hil-v2-stab.sock','--destinations','2','3','--count','20','--pace-s','1','--timeout-s','120','--out',str(out/'traffic.jsonl')],check=True)
print('HOME_RESTORED',flush=True)
