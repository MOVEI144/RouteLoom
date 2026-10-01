"""Preserve each OTA image, run radio diagnosis, and restore the SDK images."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import threading

ROOT=Path(__file__).resolve().parents[4]
OUT=ROOT/'artifacts/hil/2026-10-01-stab-review/radio-power'
OUT.mkdir(parents=True,exist_ok=True)
spec=importlib.util.spec_from_file_location('stablib',ROOT/'artifacts/hil/2026-09-30-stab/scripts/stablib.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
SOCK='/tmp/routeloom-hil-v2-stab.sock'
backups=ROOT/'build-review-probe/backups';backups.mkdir(exist_ok=True,mode=0o700)
record={'source_sha':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'images':{},'restored':{}}
changed=[]
def command(name,args,label):
    b,port=h.board(name)
    r=subprocess.run([h.ESPTOOL,'--chip',b.chip,'--port',port,'--after','no-reset',*args],capture_output=True,text=True,timeout=180)
    (OUT/f'{name}-{label}.log').write_text(r.stdout+r.stderr)
    if r.returncode:raise RuntimeError(f'{name} {label} rc={r.returncode}')
try:
    for name,chip in [('bridge','c3'),('relay','c6'),('endpoint','c6')]:
        app=ROOT/f'build-review-probe/{chip}/build/stab_radio_probe.bin'
        if not app.is_file():raise RuntimeError(f'probe build missing: {chip}')
        h.preflight(name,OUT)
        h.flash.verify_device_partition_table(h.ESPTOOL,h.board(name)[0].chip,h.board(name)[1],str(ROOT/'build-review-probe'/chip/'build'))
        saved=backups/f'{name}.bin'
        command(name,['read-flash','0x40000','0x1d0000',str(saved)],'backup')
        original=hashlib.sha256(saved.read_bytes()).hexdigest()
        record['images'][name]={'original_ota_sha256':original,'probe_sha256':hashlib.sha256(app.read_bytes()).hexdigest()}
        # Identity is checked again immediately before the app-only write.
        h.preflight(name,OUT)
        changed.append(name)
        command(name,['write-flash','--flash-mode','keep','--flash-freq','keep','--flash-size','keep','0x40000',str(app)],'probe-write')
    subprocess.run(['python3',str(ROOT/'tools/hil/reset_all.py'),'--rig',str(ROOT/'tools/hil/rigs.yaml'),'--bench','bench-2026-09-29-h0','--boards','bridge','relay','endpoint','--out',str(OUT/'reset')],check=True,stdout=(OUT/'reset.out').open('w'),stderr=subprocess.STDOUT,timeout=180)
    threads=[threading.Thread(target=h.boot_capture,args=(name,265,OUT/f'console-{name}.log',False)) for name in changed]
    for t in threads:t.start()
    for t in threads:t.join()
finally:
    errors=[]
    for name in changed:
        try:
            h.preflight(name,OUT)
            saved=backups/f'{name}.bin'
            command(name,['write-flash','--flash-mode','keep','--flash-freq','keep','--flash-size','keep','0x40000',str(saved)],'restore')
            check=backups/f'{name}-readback.bin'
            command(name,['read-flash','0x40000','0x1d0000',str(check)],'readback')
            record['restored'][name]=hashlib.sha256(check.read_bytes()).hexdigest()==record['images'][name]['original_ota_sha256']
            if not record['restored'][name]:raise RuntimeError('restore readback differs')
            h.hard_reset(name)
        except Exception as exc:errors.append(f'{name}: {exc}')
    record['restore_errors']=errors
    (OUT/'images.json').write_text(json.dumps(record,indent=2)+'\n')
    if errors:raise RuntimeError(str(errors))
print('PROBE_RESTORED',flush=True)
