#!/usr/bin/env python3
"""babystar (强网杯2026 online, PWN) interaction harness.
Frame on the wire: 1 byte type ('C','F','T','E') + big-endian uint32 length + payload.
All traffic is logged verbatim to evidence/.
Usage:
  python3 scripts/__vwNhULhZSlz4Fa-solve.py --tag name --idle 3 [--send "type:hex" ...]
  send items are separated by ';' each "X:hexbytes", sent in order with --gap seconds.
"""
import socket, struct, sys, os, time, argparse

HOST, PORT = '<target>', 36885
EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'evidence')

def parse_frames(b):
    i = 0; out = []
    while i + 5 <= len(b):
        t = chr(b[i]) if 32 <= b[i] < 127 else '?'
        n = struct.unpack('>I', b[i+1:i+5])[0]
        if n > len(b) - i - 5:
            out.append((i, t, n, b[i+5:], 'TRUNC')); break
        out.append((i, t, n, b[i+5:i+5+n], '')); i += 5 + n
    return out

def show(b, verbose=True):
    for off, t, n, p, flag in parse_frames(b):
        if t == 'E' or flag:
            print('%06x %s n=%-4d %r %s' % (off, t, n, p, flag)); continue
        if t == 'T' and len(p) >= 6:
            apid = ((p[0] & 7) << 8) | p[1]
            seq = ((p[2] & 0x3f) << 8) | p[3]
            d = p[6:]
            asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in d)
            if verbose and (n < 30 or any(32 <= c < 127 for c in d)):
                print('%06x T apid=0x%03x seq=%-4d n=%-4d %s' % (off, apid, seq, n, asc[:120]))
        elif t == 'F':
            print('%06x F n=%d %s' % (off, n, p[:120].hex()))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', default='run')
    ap.add_argument('--idle', type=float, default=2.0, help='seconds of initial reading')
    ap.add_argument('--after', type=float, default=2.5, help='seconds of reading after all sends')
    ap.add_argument('--gap', type=float, default=0.45)
    ap.add_argument('--send', default='', help='"C:hex;C:hex;F:hex"')
    ap.add_argument('--quiet-tm', action='store_true')
    a = ap.parse_args()
    s = socket.socket(); s.settimeout(4); s.connect((HOST, PORT))
    s.settimeout(0.5)
    log = bytearray()

    def pump(secs):
        end = time.time() + secs; got = b''
        while time.time() < end:
            try:
                d = s.recv(65536)
                if not d: break
                got += d; log.extend(d)
            except socket.timeout:
                pass
            except Exception as e:
                print('recv err', e); break
        return got

    pre = pump(a.idle)
    print('=== initial %d bytes' % len(pre))
    if pre: show(pre, verbose=not a.quiet_tm)
    items = [x for x in a.send.split(';') if x.strip()]
    for it in items:
        typ, hx = it.split(':', 1)
        payload = bytes.fromhex(hx.replace(' ', ''))
        fr = typ.encode() + struct.pack('>I', len(payload)) + payload
        print('=== SEND %s' % fr.hex())
        s.sendall(fr); log.extend(fr)
        r = pump(a.gap)
        if r: show(r, verbose=not a.quiet_tm)
    r = pump(a.after)
    print('=== trailing %d bytes' % len(r))
    if r: show(r, verbose=not a.quiet_tm)
    s.close()
    path = os.path.join(EV, '__vwNhULhZSlz4Fa-%s.bin' % a.tag)
    open(path, 'wb').write(bytes(log))
    print('LOGGED', path, len(log))

if __name__ == '__main__':
    main()
