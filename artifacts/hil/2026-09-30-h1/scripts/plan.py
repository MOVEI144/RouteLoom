"""P03 manual channel plan on hardware: offer -> READY -> release -> switch; 20+20 sends; cooldown; switch back.
usage: plan.py <outrel> <ch_a> <ch_b>"""
import sys, json, subprocess, time
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
outrel, ch_a, ch_b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-h1.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / 'plan.jsonl', 'a')
caps = [subprocess.Popen([sys.executable, '/tmp/routeloom-hil-v2/h1/cap.py', n, '2400', str(out / f'console-{n}.log')],
                         start_new_session=True) for n in ('relay', 'endpoint')]


def ctl(*a, timeout=30):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=timeout)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {'raw': r.stdout[-400:], 'err': r.stderr[-400:]}


def rec(step, **k):
    k['step'] = step; k['t'] = round(time.time(), 3)
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:500], flush=True)


def status():
    return ctl('site', 'channel-plan', 'status').get('result', {})


def fresh_status(limit=30):
    t0 = time.time()
    while time.time() - t0 < limit:
        s = status()
        rep = s.get('report') or {}
        if rep and rep.get('age_ms', 99999) < 4000:
            return s
        time.sleep(0.5)
    return status()


def routes_ok():
    j = ctl('nodes')
    ns = {n['node']: n for n in j.get('result', {}).get('nodes', [])}
    return all(ns.get(f'{x:016x}', {}).get('connected') and ns.get(f'{x:016x}', {}).get('next_hop') for x in (2, 3)), ns


def sends(tag, n_each=20):
    res = []
    for node in (3, 2):
        for i in range(n_each):
            r = ctl('send', str(node), (b'P03C' + bytes([node, i])).hex())
            res.append({'node': node, 'i': i, 'reply': r}); time.sleep(0.8)
    time.sleep(8)
    dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
    for s in res:
        s['delivery'] = dl.get(s['reply'].get('request'), {})
    (out / f'sends-{tag}.json').write_text(json.dumps(res, indent=1))
    return {str(node): sum(1 for s in res if s['node'] == node and s['delivery'].get('state') == 'delivered') for node in (3, 2)}


def switch(new_ch, tag):
    s = fresh_status()
    rec(f'{tag}_status_before', status=s)
    for attempt in range(8):
        time.sleep(1.0)
        t0 = time.time()
        o = ctl('site', 'channel-plan', 'offer', '--new-channel', str(new_ch))
        rec(f'{tag}_offer', reply=o, attempt=attempt)
        if o.get('ok'):
            break
        s = fresh_status()
    released = None; ready_seen = 0; t_ready = None
    while time.time() - t0 < 120:
        s = status(); rep = s.get('report') or {}
        ready_seen = max(ready_seen, rep.get('ready', 0))
        if released is None and rep.get('ready', 0) >= 2:
            t_ready = time.time()
            for attempt in range(8):
                time.sleep(1.0)
                r = ctl('site', 'channel-plan', 'release')
                if r.get('ok'):
                    break
            released = time.time(); rec(f'{tag}_release', ready=rep.get('ready'), after_offer_s=round(released - t0, 2), reply=r, attempt=attempt)
        if rep.get('active_channel') == new_ch and rep.get('age_ms', 99999) < 4000:
            break
        rec(f'{tag}_poll', report=rep)
        time.sleep(2.0)
    t_active = time.time()
    rec(f'{tag}_gateway_active', status=s, after_offer_s=round(t_active - t0, 2), ready_max=ready_seen)
    ok = False
    while time.time() - t0 < 180:
        ok, ns = routes_ok()
        if ok:
            break
        time.sleep(1)
    rec(f'{tag}_routes', ok=ok, after_offer_s=round(time.time() - t0, 2),
        nodes={k: {x: v.get(x) for x in ('connected', 'next_hop', 'rssi_dbm')} for k, v in ns.items()})
    d = sends(tag)
    rec(f'{tag}_sends', delivered=d)
    return s


rec('start', status=fresh_status())
s1 = switch(ch_b, 'forward')
rep = (s1 or {}).get('report') or {}
cool = rep.get('cooldown_ms') or 600000
rec('cooldown_wait', cooldown_ms=cool)
t_end = time.time() + cool / 1000 + 20
while time.time() < t_end:
    time.sleep(15)
    st = status().get('report') or {}
    if st.get('cooldown_ms') == 0 and st.get('age_ms', 99999) < 4000:
        break
rec('cooldown_done', status=status())
switch(ch_a, 'back')
for c in caps:
    c.terminate()
print('FLOW_DONE', flush=True)
