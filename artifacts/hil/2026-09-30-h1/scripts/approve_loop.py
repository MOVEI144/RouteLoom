import sys, json, time, socket, datetime
sock, secs, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
ROLES = {'0000000000000001': 'gateway', '0000000000000002': 'relay', '0000000000000003': 'endpoint'}
def call(method, params):
    req = {"v": 1, "request_id": f"h1-{time.time_ns()}", "method": method, "params": params}
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(10); c.connect(sock)
        c.sendall(b"API1 " + json.dumps(req, separators=(",", ":")).encode() + b"\n")
        with c.makefile("rb") as f: line = f.readline()
    return json.loads(line)
done = set()
end = time.time() + secs
with open(out, 'a') as log:
    while time.time() < end:
        try:
            r = call('join.requests.list', {})
            for q in r.get('result', {}).get('requests', []):
                dev = str(q.get('device_id', '')).lower().removeprefix('0x').zfill(16)
                jr = q.get('join_request_id')
                if dev in ROLES and jr not in done and q.get('state') in ('awaiting', 'open', 'pending', None):
                    d = call('join.decide', {"join_request_id": jr, "device_id": dev, "verdict": "allow",
                                             "role": ROLES[dev], "idempotency_key": f"h1-allow-{jr}"})
                    done.add(jr)
                    log.write(json.dumps({"t": datetime.datetime.now(datetime.timezone.utc).isoformat(), "request": q, "decision": d}) + "\n"); log.flush()
        except Exception as e:
            log.write(json.dumps({"t": time.time(), "error": str(e)[:200]}) + "\n"); log.flush()
        time.sleep(0.2)
