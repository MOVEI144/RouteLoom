"""App-only bench image control; preserve sealed NVS and restart the task daemon."""
import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('h',root/'artifacts/hil/2026-09-30-stab/scripts/stablib.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
role,bundle,label=sys.argv[1:]
out=root/'artifacts/hil/2026-10-01-stab-review'/label;out.mkdir(parents=True,exist_ok=True)
args=None
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:a=(p/'cmdline').read_bytes().decode().split('\0')[:-1]
 except (OSError,UnicodeError):continue
 if not a:continue
 if role=='bridge' and a[0].endswith('/routeloom-host') and '/tmp/routeloom-hil-v2-stab.sock' in a:
  args=a;os.kill(int(p.name),signal.SIGTERM)
 if 'python' in a[0] and len(a)>2 and Path(a[1]).resolve()==Path(__file__).parent/'capture.py' and a[2]==role:
  os.kill(int(p.name),signal.SIGTERM)
time.sleep(.5)
h.preflight(role,out)
before=h.nvs_dump(role,'review-'+label+'-before')
write=h.app_only(role,root/bundle,out)
after=h.nvs_dump(role,'review-'+label+'-after')
assert before==after
(out/'image.json').write_text(json.dumps({'write':write,'nvs_before':before,'nvs_after':after},indent=2))
h.hard_reset(role);time.sleep(2)
if args:
 subprocess.Popen(args,stdout=(out/'daemon.log').open('w'),stderr=subprocess.STDOUT,start_new_session=True)
else:
 subprocess.Popen([sys.executable,str(Path(__file__).parent/'capture.py'),role,'180',str(out/'console.log')],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT,start_new_session=True)
print(json.dumps({'role':role,'label':label,'nvs_preserved':True}),flush=True)
