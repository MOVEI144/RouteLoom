"""Summarize a C6 console: heap, stack hwm, owner occupancy, hop_accept_expired, EDHOC timings."""
import sys, re, json, statistics


def summarize(path):
    heap, owner, hop, edhoc, hs, hwm, other = [], [], [], {'ECDH': [], 'SIGN': [], 'VERIFY': []}, [], [], {}
    for line in open(path, errors='replace'):
        m = re.search(r'HIL HEAP free=(\d+) largest=(\d+) min=(\d+)', line)
        if m:
            heap.append(tuple(map(int, m.groups())))
        m = re.search(r'owner polls=(\d+) empty=(\d+) rxq_max=(\d+) max_us rx=(\d+) bootstrap=(\d+) node=(\d+) security=(\d+)', line)
        if m:
            owner.append(tuple(map(int, m.groups())))
        m = re.search(r'hop_accept_expired=(\d+)', line)
        if m:
            hop.append(int(m.group(1)))
        m = re.search(r'HIL EDHOC (ECDH|SIGN|VERIFY) us=(\d+)', line)
        if m:
            edhoc[m.group(1)].append(int(m.group(2)) / 1000)
        m = re.search(r'HIL EDHOC HANDSHAKE us=(\d+) role=(\d+) scope=(\d+) peer=(\d+) heap_free=(\d+)', line)
        if m:
            hs.append({'ms': int(m.group(1)) / 1000, 'role': int(m.group(2)), 'scope': int(m.group(3)), 'peer': int(m.group(4)), 'heap_free': int(m.group(5))})
        m = re.search(r'stack hwm (\S+) (\d+) B', line)
        if m:
            hwm.append((m.group(1), int(m.group(2))))
        for k in ('Guru Meditation', 'panic', 'BOOT_HEAP_BELOW_FLOOR', 'rst:'):
            if k in line:
                other[k] = other.get(k, 0) + 1
    r = {'lines': sum(1 for _ in open(path, errors='replace'))}
    if heap:
        r['heap_first'] = dict(zip(('free', 'largest', 'min'), heap[0]))
        r['heap_last'] = dict(zip(('free', 'largest', 'min'), heap[-1]))
        r['heap_min_of_min'] = min(x[2] for x in heap)
    if owner:
        last = owner[-1]
        r['owner_last'] = dict(zip(('polls', 'empty', 'rxq_max', 'max_rx_us', 'max_bootstrap_us', 'max_node_us', 'max_security_us'), last))
    if hop:
        r['hop_accept_expired_last'] = hop[-1]
    for k, v in edhoc.items():
        if v:
            r[f'edhoc_{k.lower()}_ms'] = {'n': len(v), 'min': round(min(v), 1), 'max': round(max(v), 1), 'median': round(statistics.median(v), 1)}
    if hs:
        r['edhoc_handshake'] = hs
    if hwm:
        by = {}
        for n, b in hwm:
            by[n] = min(by.get(n, 1 << 30), b)
        r['stack_hwm_min'] = by
    r['markers'] = other
    return r


if __name__ == '__main__':
    print(json.dumps({p: summarize(p) for p in sys.argv[1:]}, indent=1))
