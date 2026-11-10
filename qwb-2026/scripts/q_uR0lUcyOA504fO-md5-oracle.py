#!/usr/bin/env python3
"""Behavioural diff of the server's MD5 against the standard MD5.

The note server computes md5(data) and stores it as the node key; `get` looks a
node up by that 16-byte value. So the server itself is a perfect oracle:

    add(name, key, data) ; get(md5_std(data))  ->  data back   ==> md5 IS standard
                                                ->  no/short  ==> md5 WAS MODIFIED

Sweeps lengths around every MD5 padding boundary (55/56/63/64/119/120/...)
and a range of contents (zeros, 0xff, ascii, mixed) up to the 0x380 limit.
"""
import hashlib
import socket
import ssl
import struct
import sys

OP_ADD = bytes.fromhex("872a4338")
OP_GET = bytes.fromhex("3e4d9589")


def conn(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=8))
    s.settimeout(4)
    return s


def one_case(host, port, data):
    name = b"N" * 16
    key = b"K" * 16
    pkt = OP_ADD + name + key + struct.pack("<I", len(data)) + data
    s = conn(host, port)
    s.sendall(pkt)                     # one TLS record
    s.sendall(OP_GET + hashlib.md5(data).digest())
    got = b""
    try:
        while len(got) < len(data):
            c = s.recv(4096)
            if not c:
                break
            got += c
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    s.close()
    return got


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1443
    lengths = [1, 2, 3, 4, 15, 16, 17, 31, 32, 47, 48, 54, 55, 56, 57, 62, 63, 64,
               65, 79, 80, 95, 96, 111, 112, 118, 119, 120, 121, 127, 128, 129,
               191, 192, 200, 255, 256, 300, 0x37f, 0x380]
    fills = [b"A", b"\x00", b"\xff", b"\n", b"\x80"]
    bad = []
    total = 0
    for L in lengths:
        for f in fills:
            data = (f * L)[:L]
            total += 1
            got = one_case(host, port, data)
            ok = got == data
            if not ok:
                bad.append((L, f, len(got)))
                print("MISMATCH len=%d fill=%r got=%d bytes %s" % (L, f, len(got), got[:24].hex()))
    print("\n%d cases, %d mismatches" % (total, len(bad)))
    print("VERDICT:", "md5 is STANDARD for every reachable input" if not bad
          else "md5 DIFFERS for %r" % (bad,))


if __name__ == "__main__":
    main()
