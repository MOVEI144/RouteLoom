"""P03 remote config on hardware: challenge -> propose -> ACTIVE -> readback -> target reset -> readback.
usage: cfg.py <outrel> <target_node_int> <level_hex> [negative]"""
import sys, json, subprocess, time, pathlib
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel, node, level, base = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'; NET = '000000007364b05e'
T = f'{node:016x}'
NAME = {2: 'relay', 3: 'endpoint'}[node]
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / f'cfg-node{node}.jsonl', 'a')


def ctl(*a):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=40)
    txt = r.stdout.strip().splitlines()
    for line in reversed(txt):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {'raw': r.stdout[-400:], 'err': r.stderr[-400:]}


def wait_op(op, limit=40):
    t0 = time.time(); seen = []
    while time.time() - t0 < limit:
        j = ctl('config-get', '--id', op)
        st = j.get('result', {}).get('state')
        if not seen or seen[-1] != st:
            seen.append(st)
        if st not in (None, 'PENDING', 'SUBMITTED', 'IN_FLIGHT'):
            return j, seen
        time.sleep(0.1)
    return j, seen


def rec(step, **k):
    k['step'] = step; k['t'] = time.time()
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:600], flush=True)


def challenge(tag):
    t0 = time.time()
    s = ctl('config-challenge', '--network', NET, '--target', T, '--config-namespace', '1', '--schema', '1')
    op = s.get('result', {}).get('config_op')
    j, seen = wait_op(op) if op else (s, [])
    c = j.get('result', {}).get('challenge', {})
    rec(tag, op=op, states=seen, revision=c.get('revision'), active_hash=c.get('active_hash'),
        target_boot=c.get('target_boot'), elapsed_s=round(time.time() - t0, 3), raw=None if c else j)
    return c


c0 = challenge('challenge_before')
if len(sys.argv) > 5:
    # negative: wrong field type for diagnostics_level; must not activate
    t0 = time.time()
    s = ctl('config-propose', '--network', NET, '--target', T, '--config-namespace', '1', '--schema', '1',
            '--base-snapshot', base, '--field', '1:bytes:0002')
    op = s.get('result', {}).get('config_op')
    j, seen = wait_op(op) if op else (s, [])
    rec('negative_wrong_type', op=op, states=seen, result=j.get('result', j), elapsed_s=round(time.time() - t0, 3))
    challenge('challenge_after_negative')
    time.sleep(65)  # the target admits one new update per minute
t0 = time.time()
s = ctl('config-propose', '--network', NET, '--target', T, '--config-namespace', '1', '--schema', '1',
        '--base-snapshot', base, '--field', f'1:u8:{level}')
op = s.get('result', {}).get('config_op')
j, seen = wait_op(op) if op else (s, [])
st = j.get('result', {}).get('status', {})
rec('propose', op=op, states=seen, phase=st.get('phase'), reason=st.get('reason'), active_revision=st.get('active_revision'),
    active_hash=st.get('active_hash'), operation_id=st.get('operation_id'), elapsed_s=round(time.time() - t0, 3),
    submitted_ms=s.get('result', {}).get('submitted_ms'), resolved_ms=j.get('result', {}).get('resolved_ms'))
opid = st.get('operation_id')
for _ in range(20):
    if st.get('phase') == 'ACTIVE' or not opid:
        break
    time.sleep(0.5)
    s2 = ctl('config-status', '--network', NET, '--target', T, '--config-namespace', '1', '--operation-id', opid)
    op2 = s2.get('result', {}).get('config_op')
    j2, seen2 = wait_op(op2) if op2 else (s2, [])
    st = j2.get('result', {}).get('status', {})
    rec('status_poll', phase=st.get('phase'), active_revision=st.get('active_revision'), elapsed_s=round(time.time() - t0, 3))
c1 = {}
for i in range(5):
    c1 = challenge(f'readback_after_apply_try{i}')
    if c1.get('revision') is not None:
        break
    time.sleep(3)
rec('readback_match', ok=(c1.get('revision') == st.get('active_revision') and c1.get('active_hash') == st.get('active_hash')))
# reset the target (EN via RTS) and read back again after it rejoins
lines = h.boot_capture(NAME, 25, out / f'reset-node{node}-boot.log', reset=True)
lv = [l for l in lines if 'config' in l.lower() or 'diagnostic' in l.lower()][:20]
rec('target_reset', boot_lines=len(lines), config_lines=lv)
for i in range(12):
    c2 = challenge(f'readback_after_reset_try{i}')
    if c2.get('revision') is not None:
        break
    time.sleep(5)
rec('reset_readback_match', ok=(c2.get('revision') == c1.get('revision') and c2.get('active_hash') == c1.get('active_hash')),
    boot_changed=c2.get('target_boot') != c1.get('target_boot'))
print('FLOW_DONE')
