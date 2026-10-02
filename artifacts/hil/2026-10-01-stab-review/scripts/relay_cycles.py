"""Install the existing HIL RX filters, verify the forced path, then run M06-R."""
import importlib.util,json,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[4];out=root/'artifacts/hil/2026-10-01-stab-review/relay-reset';out.mkdir(parents=True,exist_ok=True)
def run(*a,**kw):return subprocess.run(list(a),check=True,**kw)
for role,label in (('endpoint','review-chain-ep'),('bridge','review-chain-br')):
 run(sys.executable,str(Path(__file__).parent/'switch_image.py'),role,'artifacts/hil/images/'+label,'chain-install-'+role)
run(sys.executable,str(Path(__file__).parent/'boot_fresh.py'),'chain-boot')
base=[str(root/'host/target/debug/routeloomctl'),'--socket','/tmp/routeloom-hil-v2-stab.sock']
view=json.loads(subprocess.check_output(base+['nodes'],text=True));(out/'forced-path.json').write_text(json.dumps(view,indent=2))
n=next(n for n in view['result']['nodes'] if n['node']=='0000000000000003')
assert n.get('connected') and str(n.get('next_hop')).lower() in ('2','0000000000000002'),n
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:a=(p/'cmdline').read_bytes().decode().split('\0')
 except (OSError,UnicodeError):continue
 if len(a)>2 and 'python' in a[0] and Path(a[1]).resolve()==Path(__file__).parent/'capture.py' and a[2]=='relay':
  import os,signal;os.kill(int(p.name),signal.SIGTERM)
time.sleep(.3)
args=[sys.executable,str(root/'tools/hil/reset_cycles.py'),'--rig',str(root/'tools/hil/rigs.yaml'),'--bench','bench-2026-09-29-h0','--board','relay','--ctl',base[0],'--socket',base[2],'--destination','3','--cycles','10','--sends','10','--baseline','3','--send-gap-s','1','--poll-timeout-s','9','--out',str(out)]
r=subprocess.run(args);print('RESET_EXIT',r.returncode,flush=True)
