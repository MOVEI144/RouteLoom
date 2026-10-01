"""Offer + release one channel plan (all required members READY). usage: move.py <outrel> <new_ch>"""
import sys, json, subprocess, time
sys.path.insert(0, '/tmp/routeloom-hil-v2/stab')
import stablib as h
outrel, ch = sys.argv[1], int(sys.argv[2])
CTL = h.CTL; SOCK = '/tmp/routeloom-hil-v2-stab.sock'
out = h.RUN / outrel; out.mkdir(parents=True, exist_ok=True)
log = open(out / 'move.jsonl', 'a')


def ctl(*a):
    r = subprocess.run([CTL, '--socket', SOCK, *a], capture_output=True, text=True, timeout=30)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except Exception:
            pass
    return {}


def rec(step, **k):
    k['step'] = step; k['t'] = round(time.time(), 3)
    log.write(json.dumps(k) + '\n'); log.flush(); print(json.dumps(k)[:300], flush=True)


def fresh():
    # One status request at a time: the gateway desk takes one request.
    for _ in range(20):
        s = ctl('site', 'channel-plan', 'status').get('result', {})
        rep = s.get('report') or {}
        if rep and rep.get('age_ms', 99999) < 3000:
            return s
        time.sleep(1.5)
    return s


fresh()
t0 = time.time()
for _ in range(10):
    time.sleep(1.5)  # let the status request complete: the desk takes one at a time
    o = ctl('site', 'channel-plan', 'offer', '--new-channel', str(ch))
    if o.get('ok'):
        break
    time.sleep(1.5); fresh()
rec('offer', reply=o)
released = False
while time.time() - t0 < 120:
    s = fresh(); rep = s.get('report') or {}
    if not released and rep.get('ready', 0) >= s.get('required', 99):
        for _ in range(10):
            time.sleep(1.5)
            r = ctl('site', 'channel-plan', 'release')
            if r.get('ok'):
                released = True
                break
            time.sleep(1.5); fresh()
        rec('release', reply=r, after_offer_s=round(time.time() - t0, 2), ready=rep.get('ready'))
    if rep.get('active_channel') == ch:
        break
    time.sleep(2)
rec('done', report=rep, after_offer_s=round(time.time() - t0, 2))
