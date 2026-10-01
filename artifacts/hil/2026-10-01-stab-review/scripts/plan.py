"""Strict 6->1->6 acceptance. Never release without fresh full READY.
Hold the endpoint only after READY for the return; close its console first.
"""
import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('h',root/'artifacts/hil/2026-09-30-stab/scripts/stablib.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
out=root/'artifacts/hil/2026-10-01-stab-review'/sys.argv[1];out.mkdir(parents=True,exist_ok=True)
f=(out/'plan.jsonl').open('w');base=[h.CTL,'--socket','/tmp/routeloom-hil-v2-stab.sock'];caps={}
def ctl(*a):
 r=subprocess.run(base+list(a),capture_output=True,text=True,timeout=30)
 try:return json.loads(r.stdout)
 except ValueError:return {'raw':r.stdout,'err':r.stderr}
def rec(step,**kw):
 row=dict(step=step,wall=time.time(),mono=time.monotonic(),**kw);f.write(json.dumps(row)+'\n');f.flush();print(json.dumps(row)[:500],flush=True)
def status():return ctl('site','channel-plan','status').get('result',{})
def capture(role):
 caps[role]=subprocess.Popen([sys.executable,str(Path(__file__).parent/'capture.py'),role,'2400',str(out/f'console-{role}-{len(list(out.glob("console*")))}.log')],start_new_session=True)
def traffic(tag,started,limit):
 rows=[]
 for i in range(20):
  for n in (2,3):
   rows.append({'node':n,'index':i,'reply':ctl('send',str(n),(tag+f'-{n}-{i}').encode().hex())})
   time.sleep(.3)
 while time.monotonic()-started<limit:
  dl={d['request']:d for d in ctl('deliveries').get('deliveries',[])}
  for r in rows:
   d=dl.get(r['reply'].get('request'));r['delivery']=d or {}
   if d and d.get('state') in {'delivered','expired','failed','rejected','cancelled','indeterminate'} and 'terminal_s' not in r:r['terminal_s']=time.monotonic()-started
  if all('terminal_s' in r or not r['reply'].get('accepted') for r in rows):break
  time.sleep(.1)
 rec(tag+'_traffic',limit_s=limit,after_switch_s=time.monotonic()-started,delivered={str(n):sum(r['node']==n and r['delivery'].get('state')=='delivered' and r.get('terminal_s',1e9)<=limit for r in rows) for n in (2,3)},rows=rows)
def switch(ch,tag,miss=False):
 until=time.monotonic()+15
 while time.monotonic()<until:
  s=status();p=s.get('report') or {}
  if p.get('age_ms',999999)<4000:break
  time.sleep(.3)
 rec(tag+'_before',status=s)
 for attempt in range(8):
  time.sleep(.5);r=ctl('site','channel-plan','offer','--new-channel',str(ch));rec(tag+'_offer',reply=r,attempt=attempt)
  if r.get('ok'):break
  if r.get('error',{}).get('code')!='BUSY':break
 if not r.get('ok'):return False
 started=time.monotonic();released=False;held=False
 while time.monotonic()-started<130:
  s=status();p=s.get('report') or {}
  if not released and p.get('age_ms',999999)<4000 and p.get('ready',0)==s.get('required',2)==2:
   if miss:
    caps['endpoint'].terminate();caps['endpoint'].wait(timeout=5);h.preflight('endpoint',out/'hold-preflight');h.hold_rom('endpoint');held=True;rec(tag+'_held')
   for attempt in range(8):
    time.sleep(.3);r=ctl('site','channel-plan','release');rec(tag+'_release',reply=r,status=s,attempt=attempt)
    if r.get('ok'):break
    if r.get('error',{}).get('code')!='BUSY':break
   if not r.get('ok'):break
   released=True
  if released and p.get('age_ms',999999)<4000 and p.get('active_channel')==ch:
   switched=time.monotonic();rec(tag+'_active',status=s,after_offer_s=switched-started)
   if held:
    h.hard_reset('endpoint');time.sleep(2);capture('endpoint');rec(tag+'_miss_released');traffic(tag,switched,120)
   else:traffic(tag,switched,60)
   return True
  time.sleep(.5)
 rec(tag+'_not_completed',released=released,miss_started=held,status=status())
 if held:h.hard_reset('endpoint');time.sleep(2);capture('endpoint')
 return False
try:
 for role in ('relay','endpoint'):capture(role)
 rec('start',status=status(),members=ctl('site','members'))
 if switch(1,'forward'):
  rec('cooldown_wait');deadline=time.monotonic()+650
  while time.monotonic()<deadline:
   p=status().get('report') or {}
   if p.get('age_ms',999999)<4000 and p.get('cooldown_ms')==0:break
   time.sleep(5)
  rec('cooldown_done',status=status());switch(6,'back',True)
finally:
 for p in caps.values():
  if p.poll() is None:p.terminate()
 f.close()
