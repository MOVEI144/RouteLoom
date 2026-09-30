import sys, subprocess, json, re, pathlib, time, glob
R='/home/sahur/orca/workspaces/RouteLoom/v2-h1/'
sys.path.insert(0, R+'tools/hil')
import flash, rig
out=pathlib.Path(R+'artifacts/hil/2026-09-30-h1/erase'); out.mkdir(parents=True, exist_ok=True)
bench=rig.load_rigs(R+'tools/hil/rigs.yaml')['bench-2026-09-29-h0']
E='/home/sahur/.local/bin/esptool'; F='/home/sahur/.local/bin/espefuse'
res={}
do_erase='--erase' in sys.argv
names=[a for a in sys.argv[1:] if not a.startswith('--')] or ['bridge','relay','endpoint']
for name in names:
    b=bench.boards[name]
    for i in range(600):
        port,_,st=rig.resolve_board_port(b)
        if st=='ONLINE': break
        time.sleep(0.1)
    # enter ROM and hold it there (no reset after) so a sleeping image cannot leave
    subprocess.run([E,'--chip',b.chip,'--port',port,'--after','no-reset','chip-id'],capture_output=True,text=True,timeout=60)
    ident=flash.preflight_board(b, port, E, str(out), minimum_flash_bytes=4*1024*1024)
    r={'identity':ident}
    fe=subprocess.run([F,'--port',port,'--chip',b.chip,'--after','no-reset','summary'],capture_output=True,text=True,timeout=60)
    (out/f'{name}-efuse-summary.log').write_text(fe.stdout+fe.stderr)
    r['efuse_rc']=fe.returncode
    for key in ['SPI_BOOT_CRYPT_CNT','SECURE_BOOT_EN','DIS_DOWNLOAD_MODE','WR_DIS','RD_DIS','KEY_PURPOSE_0']:
        m=re.search(r'^'+key+r'\s.*?=\s*(.+)$', fe.stdout, re.M)
        if m: r[key]=m.group(1).strip()[:80]
    if do_erase:
        t=time.monotonic()
        er=subprocess.run([E,'--chip',b.chip,'--port',port,'erase-flash'],capture_output=True,text=True,timeout=180)
        (out/f'{name}-erase.log').write_text(er.stdout+er.stderr)
        r['erase_rc']=er.returncode; r['erase_s']=round(time.monotonic()-t,1)
    res[name]=r
    print(name, json.dumps(r), flush=True)
(out/('summary-erase.json' if do_erase else 'summary-inventory.json')).write_text(json.dumps(res,indent=2))
