"""Manual channel plan on hardware: 6->1 (all members), cooldown, 1->6 with the endpoint
held in the ROM across the release (it misses the switch), then released.
usage: plan.py <outrel> <ch_a> <ch_b>"""
import sys, json, subprocess, time
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[2] / '2026-09-30-stab/scripts'))
import stablib as h
h.RUN = __import__('pathlib').Path(__file__).resolve().parents[1]
import os
outrel, ch_a, ch_b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
NODES = tuple(int(x) for x in os.environ.get('PLAN_NODES', '2 3').split())
MISS = os.environ.get('PLAN_MISS', 'endpoint')
MISS_NODE = int(os.environ.get('PLAN_MISS_NODE', '3'))
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-stab.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / 'plan.jsonl', 'a')
caps = [subprocess.Popen([sys.executable, str(h.RUN / 'scripts/run.py'), 'cap.py', n, '2400', str(out / f'console-{n}.log')],
                         start_new_session=True) for n in ('relay', 'endpoint')]
time.sleep(1)


def ctl(*a, timeout=30):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=timeout)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {'raw': r.stdout[-400:], 'err': r.stderr[-400:]}


def rec(step, **k):
    k['step'] = step; k['monotonic_s'] = round(time.monotonic(), 3); k['utc'] = h.stamp()
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:400], flush=True)


def status():
    return ctl('site', 'channel-plan', 'status').get('result', {})


def fresh_status(limit=30):
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        s = status()
        rep = s.get('report') or {}
        if rep and rep.get('age_ms', 99999) < 4000:
            return s
        time.sleep(0.5)
    return status()


def route(node):
    j = ctl('nodes')
    ns = {n['node']: n for n in j.get('result', {}).get('nodes', [])}
    n = ns.get(f'{node:016x}', {})
    return bool(n.get('connected') and n.get('next_hop')), ns


def sends(tag, nodes, n_each=20):
    res = []
    for node in nodes:
        for i in range(n_each):
            r = ctl('send', str(node), (b'STAB' + bytes([node, i])).hex())
            res.append({'node': node, 'i': i, 'reply': r, 't': time.monotonic()}); time.sleep(0.8)
    time.sleep(8)
    dl = {d['request']: d for d in ctl('deliveries').get('deliveries', [])}
    for s in res:
        s['delivery'] = dl.get(s['reply'].get('request'), {})
    (out / f'sends-{tag}.json').write_text(json.dumps(res, indent=1))
    return {str(node): sum(1 for s in res if s['node'] == node and s['delivery'].get('state') == 'delivered')
            for node in nodes}


def switch(new_ch, tag, miss_endpoint=False):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        nodes = ctl('nodes').get('result', {}).get('nodes', [])
        direct = {int(n['node'], 16) for n in nodes if n.get('neighbor') and n.get('connected')}
        if set(NODES) <= direct:
            break
        time.sleep(1)
    assert set(NODES) <= direct, 'required members are not bound directly'
    rec(f'{tag}_status_before', status=fresh_status())
    for attempt in range(8):
        time.sleep(1.0)
        t0 = time.monotonic()
        o = ctl('site', 'channel-plan', 'offer', '--new-channel', str(new_ch))
        rec(f'{tag}_offer', reply=o, attempt=attempt)
        if o.get('ok'):
            break
        fresh_status()
        time.sleep(1.5)
    released = None
    while time.monotonic() - t0 < 120:
        s = status(); rep = s.get('report') or {}
        if released is None and rep.get('ready', 0) >= s.get('required', 2):
            if miss_endpoint:
                cap = caps[0] if MISS == 'relay' else caps[1]
                cap.terminate(); cap.wait()
                h.hold_rom(MISS)
                rec(f'{tag}_endpoint_held_in_rom')
            for attempt in range(8):
                r = ctl('site', 'channel-plan', 'release')
                if r.get('ok'):
                    break
                fresh_status()
                time.sleep(1.5)
            released = time.monotonic()
            rec(f'{tag}_release', ready=rep.get('ready'), after_offer_s=round(released - t0, 2), reply=r, attempt=attempt)
        if rep.get('active_channel') == new_ch and rep.get('age_ms', 99999) < 4000:
            break
        time.sleep(2.0)
    t_active = time.monotonic()
    rec(f'{tag}_gateway_active', status=s, after_offer_s=round(t_active - t0, 2))
    targets = tuple(n for n in NODES if not (miss_endpoint and n == MISS_NODE))
    while time.monotonic() - t_active < 60 and not all(route(n)[0] for n in targets):
        time.sleep(1)
    rec(f'{tag}_routes', nodes=list(targets), ok=all(route(n)[0] for n in targets),
        after_switch_s=round(time.monotonic() - t_active, 2))
    rec(f'{tag}_sends', delivered=sends(tag, targets), after_switch_s=round(time.monotonic() - t_active, 2))
    if miss_endpoint:
        time.sleep(5)
        cap = caps[0] if MISS == 'relay' else caps[1]
        cap.terminate(); cap.wait()
        t_rel = time.monotonic()
        h.hard_reset(MISS)
        time.sleep(2)
        caps.append(subprocess.Popen([sys.executable, str(h.RUN / 'scripts/run.py'), 'cap.py', MISS, '600',
                                      str(out / f'console-{MISS}.log')], start_new_session=True))
        rec(f'{tag}_missed_released', board=MISS)
        while time.monotonic() - t_rel < 120 and not route(MISS_NODE)[0]:
            time.sleep(1)
        rec(f'{tag}_missed_route', ok=route(MISS_NODE)[0], after_release_s=round(time.monotonic() - t_rel, 2))
        rec(f'{tag}_missed_sends', delivered=sends(f'{tag}-missed', NODES),
            after_release_s=round(time.monotonic() - t_rel, 2))


rec('start', status=fresh_status())
switch(ch_b, 'forward')
rec('cooldown_wait')
t_end = time.monotonic() + 640
while time.monotonic() < t_end:
    time.sleep(15)
    st = (status().get('report') or {})
    if st.get('cooldown_ms') == 0 and st.get('age_ms', 99999) < 4000:
        break
rec('cooldown_done', status=status())
switch(ch_a, 'back', miss_endpoint=True)
for c in caps:
    c.terminate()
print('FLOW_DONE', flush=True)
