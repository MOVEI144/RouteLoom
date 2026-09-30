"""H0 bench helpers: setup-image BoardConfig, identity, app-only rewrite, NVS hashes."""
import hashlib, json, os, pathlib, subprocess, sys, tempfile, time, datetime
REPO = pathlib.Path('/home/sahur/orca/workspaces/RouteLoom/v2-h1')
sys.path.insert(0, str(REPO / 'tools/hil'))
sys.path.insert(0, str(REPO / 'tools/meshviz/src'))
import flash, rig  # noqa
import serial  # noqa
from routeloom_meshviz import provisioning as pv  # noqa
from routeloom_meshviz.firmware_catalog import DEV_PUBLIC_KEY, verify_bundle  # noqa

ESPTOOL = flash.DEFAULT_ESPTOOL
PRIV = pathlib.Path('/tmp/routeloom-hil-v2')
CTL = str(REPO / 'host/target/debug/routeloomctl')
RUN = REPO / 'artifacts/hil/2026-09-30-h1'
BENCH = rig.load_rigs(str(REPO / 'tools/hil/rigs.yaml'))[os.environ.get('H0_BENCH', 'bench-2026-09-29-h0')]
# NVS regions of PT-4M-v2 (label, offset, size)
NVS = (('rlcfg', 0x12000, 0x6000), ('rlkeys', 0x18000, 0x3000), ('rlsec', 0x20000, 0x20000))
STA_MAC = {'bridge': '94:a9:90:7a:26:ac', 'relay': '10:bd:a3:b1:48:a8', 'endpoint': '10:bd:a3:b1:47:54',
           'swap-bridge': '10:bd:a3:b1:47:54', 'swap-ref': '94:a9:90:7a:26:ac'}


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')


def board(name):
    b = BENCH.boards[name]
    port, _, st = rig.resolve_board_port(b)
    if st != 'ONLINE':
        raise RuntimeError(f'{name} {st}')
    return b, port


def preflight(name, out):
    b, port = board(name)
    os.makedirs(out, exist_ok=True)
    return flash.preflight_board(b, port, ESPTOOL, str(out), minimum_flash_bytes=0x400000)


def full_flash(name, bundle, out, boot_seconds=4.0):
    b, port = board(name)
    m = flash.flash_board(b, port, str(out), image_dir=str(bundle), boot_seconds=boot_seconds)
    (pathlib.Path(out) / f'flash-{name}.json').write_text(json.dumps(m, indent=2, sort_keys=True))
    if not m['ok']:
        raise RuntimeError(f'full flash {name}: {m["error"]}')
    return m


def nvs_dump(name, label):
    """Read the three NVS partitions (ROM session, no app boot) into PRIV; return hashes."""
    b, port = board(name)
    d = PRIV / 'nvs' / name
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / f'{label}.bin'
    r = subprocess.run([ESPTOOL, '--chip', b.chip, '--port', port, '-b', '921600',
                        '--after', 'no-reset', 'read-flash', '0x12000', '0x2e000', str(path)],
                       capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    os.chmod(path, 0o600)
    data = path.read_bytes()
    out = {}
    for lab, off, size in NVS:
        chunk = data[off - 0x12000: off - 0x12000 + size]
        out[lab] = {'sha256': hashlib.sha256(chunk).hexdigest(),
                    'blank': chunk == b'\xff' * size}
    return out


def hard_reset(name):
    b, port = board(name)
    subprocess.run([ESPTOOL, '--chip', b.chip, '--port', port, '--after', 'hard-reset', 'chip-id'],
                   capture_output=True, text=True, timeout=60)


def app_only(name, bundle, out):
    """Preflight, verify PT-4M-v2 on device, write ota_0 + blank otadata without booting."""
    b, port = board(name)
    bundle = pathlib.Path(bundle)
    signed = verify_bundle(bundle, DEV_PUBLIC_KEY)
    if signed['chip'] != b.chip or signed['role'] != b.app:
        raise RuntimeError('bundle/board mismatch')
    os.makedirs(out, exist_ok=True)
    ident = preflight(name, out)
    with tempfile.TemporaryDirectory() as td:
        pt = pathlib.Path(td) / 'partition_table'
        pt.mkdir()
        (pt / 'partition-table.bin').write_bytes((bundle / 'images/partition_table/partition-table.bin').read_bytes())
        flash.verify_device_partition_table(ESPTOOL, b.chip, port, td)
    ota = (bundle / 'images/ota_data_initial.bin').read_bytes()
    if ota != b'\xff' * len(ota):
        raise RuntimeError('otadata not blank')
    cmd = [ESPTOOL, '--chip', b.chip, '--port', port, '-b', '460800', '--after', 'no-reset',
           'write-flash', '--flash-mode', 'keep', '--flash-freq', 'keep', '--flash-size', 'keep',
           '0x10000', str(bundle / 'images/ota_data_initial.bin'),
           '0x40000', str(bundle / 'images/application.bin')]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    (pathlib.Path(out) / f'app-only-{name}-esptool.log').write_text(' '.join(cmd) + '\n' + r.stdout + r.stderr)
    if r.returncode:
        raise RuntimeError(f'app-only write failed rc={r.returncode}')
    app = bundle / 'images/application.bin'
    return {'identity': ident, 'app_sha256': hashlib.sha256(app.read_bytes()).hexdigest(),
            'app_bytes': app.stat().st_size, 'bundle': signed['bundle_id']}


def boot_capture(name, seconds, path, reset=True):
    """Open the USB console (DTR on), optionally pulse EN via RTS, log timestamped lines.

    A C6 can drop and re-enumerate its USB Serial/JTAG link while the app starts;
    the capture reopens the pinned by-id port and keeps logging until the deadline.
    """
    b, port = board(name)
    lines = []
    end = time.monotonic() + seconds
    first = True
    with open(path, 'w') as log:
        while time.monotonic() < end:
            try:
                s = serial.Serial(port=None, baudrate=115200, timeout=0.1)
                s.dtr = True
                s.rts = False
                s.port = port
                s.open()
            except (OSError, serial.SerialException) as exc:
                time.sleep(0.05)
                continue
            if not first:
                log.write(f'[{stamp()}] !! reopened after USB drop\n')
            try:
                if reset and first:
                    s.dtr = False; s.rts = True; time.sleep(0.2); s.rts = False; s.dtr = True
                    log.write(f'[{stamp()}] !! reset pulse\n')
                first = False
                buf = b''
                while time.monotonic() < end:
                    data = s.read(4096)
                    if not data:
                        continue
                    buf += data
                    while b'\n' in buf:
                        line, buf = buf.split(b'\n', 1)
                        t = line.decode('utf-8', 'replace').rstrip()
                        lines.append(t)
                        log.write(f'[{stamp()}] {t}\n')
                        log.flush()
            except (OSError, serial.SerialException) as exc:
                first = False
                log.write(f'[{stamp()}] !! USB serial error: {str(exc)[:80]}\n')
            finally:
                try:
                    s.close()
                except Exception:
                    pass
    return lines


def console_link(name):
    b, port = board(name)
    return pv.SerialMaintenanceLink(port, timeout_s=20.0)


def site_psk(site):
    path = pathlib.Path(site) / 'mesh-psk.key'
    if path.is_file():
        return path.read_text().strip()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    s = os.urandom(32).hex()
    os.write(fd, s.encode()); os.close(fd)
    return s


def commit_config(name, site, node_hex, security, role, generation=1):
    spec = json.loads((pathlib.Path(str(site) + '.lab-spec.json')).read_text())
    doc = pv.rlc1_document(node_id=node_hex, sta_mac=STA_MAC[name], chip=BENCH.boards[name].chip,
                           role=role, security=security, channel=spec['channel'],
                           network=spec['network_low32'])
    link = console_link(name)
    try:
        link.reset(settle_s=3.0)
        usb = (pathlib.Path(site) / 'usb-dev-secret.key').read_text().strip() if role == 'bridge' else None
        ev = pv.board_config_commit(link, doc, generation=generation,
                                    psk_hex=site_psk(site) if security == 'dev-ram' else None,
                                    usb_secret=usb)
    finally:
        link.close()
    return ev
