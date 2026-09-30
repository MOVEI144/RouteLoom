"""Continuous console capture of one board (no reset), reopening after USB drops.
usage: cap.py <board> <seconds> <outfile>"""
import sys, time, datetime, serial
sys.path.insert(0, '/tmp/routeloom-hil-v2/h1')
import h1lib as h
name, secs, path = sys.argv[1], float(sys.argv[2]), sys.argv[3]
b = h.BENCH.boards[name]
end = time.monotonic() + secs
def st(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
with open(path, 'a') as log:
    while time.monotonic() < end:
        try:
            import rig
            port, _, s_ = rig.resolve_board_port(b)
            if s_ != 'ONLINE': time.sleep(0.1); continue
            s = serial.Serial(port=None, baudrate=115200, timeout=0.2); s.dtr = True; s.rts = False; s.port = port; s.open()
        except Exception:
            time.sleep(0.1); continue
        log.write(f'[{st()}] !! opened\n'); log.flush()
        buf = b''
        try:
            while time.monotonic() < end:
                d = s.read(4096)
                if not d: continue
                buf += d
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    log.write(f'[{st()}] {line.decode("utf-8","replace").rstrip()}\n')
                log.flush()
        except Exception as e:
            log.write(f'[{st()}] !! USB error {str(e)[:60]}\n'); log.flush()
        finally:
            try: s.close()
            except Exception: pass
