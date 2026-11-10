#!/usr/bin/env python3
"""easytl (QWB 2026, q_uR0lUcyOA504fO) -- TLS client + command protocol harness.

Reverse-engineered from firmware/qwbq_uR0lUcyOA504fO_easytl/easytl (static OpenSSL).

Protocol (per connection; server forks one child per TCP connection, so all
state is per-connection and dies with it):
  4-byte little-endian opcode, then a payload that the server reads
  BYTE-AT-A-TIME up to a max, stopping on 0x0a (converted to NUL).
  Unknown opcode -> server writes 5 bytes "error".

Opcode table (value = LE bytes):
  0x38432a87  add   : name[16] || key[16] || u32 size(1..0x380) || data[size]
                      -> node{ md5(data)[16], pad[16], name[16], key[16],
                               data*, size }
                      (max 0x40 nodes)
  0x6c5a5850  enc   : md5[16]  -> CFB-128 encrypt node->data in place
                      (AES key = name[16], IV = key field[16])
  0x363bbed5  dec   : md5[16]  -> CFB-128 decrypt node->data in place
  0x89954d3e  get   : md5[16]  -> writes data[size] back
  0xdc375626  edit  : md5[16] || u32 newsize(1..0x380) || newdata[newsize]
  0xd21fef03  del   : md5[16]  -> unlink + free(data) + free(node)

  Lookup key is ALWAYS the first 16 bytes of md5(data), so the client must
  compute it.  Empirically verified with gdb (node[0:16] == md5(data)).

Two unreachable-looking "magic" branches (constants in .rodata):
  get  : if md5(data) == 66558c3de56c1d3eddb3e8c3ec59e6d1 (0x825109)
         -> strcat("data: ", data) into a 0x58-byte stack buffer (canary-guarded)
  edit : if md5(data) == 66448c3de56c4d3e11b3e8c4ec59e6d1 (0x82511a)
         -> free(node->data) WITHOUT clearing it => dangling pointer
Both need an MD5 preimage; the two constants share 12/16 bytes, so they cannot
both be md5() outputs (=> likely decoys / author backdoor).

Hidden TLS layer (set in 0x4032bb on SSL_CTX):
  SNI callback  0x40320a : copies servername (<=255 B) to calloc(strlen+0x10)
  info callback 0x4030d5 : on SSL alert it can call 0x40304d
  0x40304d               : char buf[0x50]; memcpy(buf, G_970f60, G_970f68);
                           fprintf(stdout, "%s error\n", buf)
                           G_970f68 can be strlen(SNI) => stack overflow, but
                           the source is a 0x30-byte heap chunk (identity) so
                           the bytes past +0x30 are not attacker controlled.
  PSK find-session cb 0x402dbb : requires TLS1.3 external-PSK identity
                           EXACTLY "1401518dc5d7641ccd41593a5d812410";
                           derives a session from hardcoded hex strings
                           (0x825060: c8ad..6f08 07ff..b358) and returns it.
                           With openssl s_client the callback IS reached but
                           OpenSSL then aborts with
                           "tls_parse_ctos_psk: bad extension".

Usage:
  python3 q_uR0lUcyOA504fO-solve.py probe [host] [port]
  python3 q_uR0lUcyOA504fO-solve.py demo  [host] [port]
"""
import hashlib
import socket
import ssl
import struct
import sys

OP_ADD = bytes.fromhex("872a4338")
OP_ENC = bytes.fromhex("50585a6c")
OP_DEC = bytes.fromhex("d5be3b36")
OP_GET = bytes.fromhex("3e4d9589")
OP_EDIT = bytes.fromhex("265637dc")
OP_DEL = bytes.fromhex("03ef1fd2")

MAGIC1 = bytes.fromhex("66558c3de56c1d3eddb3e8c3ec59e6d1")
MAGIC2 = bytes.fromhex("66448c3de56c4d3e11b3e8c4ec59e6d1")
PSK_ID = b"1401518dc5d7641ccd41593a5d812410"


class Conn:
    def __init__(self, host, port, sni=None, timeout=8):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        self.s = ctx.wrap_socket(sock, server_hostname=sni or "easytl")
        self.s.settimeout(timeout)

    def cmd(self, op, payload=b""):
        self.s.sendall(op + payload)

    def recv(self, n, timeout=2.0):
        self.s.settimeout(timeout)
        out = b""
        try:
            while len(out) < n:
                c = self.s.recv(n - len(out))
                if not c:
                    break
                out += c
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def h(data):
    return hashlib.md5(data).digest()


def add(c, name, key, data):
    assert len(name) == 16 and len(key) == 16 and 0 < len(data) <= 0x380
    assert b"\n" not in data
    c.cmd(OP_ADD, name + key + struct.pack("<I", len(data)) + data)
    return h(data)


def get(c, digest, n):
    c.cmd(OP_GET, digest)
    return c.recv(n)


def edit(c, digest, data):
    # the digest read is a SEPARATE SSL_read that must return exactly 16 bytes,
    # so opcode+digest go in one TLS record and size+data in the next one
    c.cmd(OP_EDIT, digest)
    c.s.sendall(struct.pack("<I", len(data)) + data)
    return h(data)


def delete(c, digest):
    c.cmd(OP_DEL, digest)


def enc(c, digest):
    c.cmd(OP_ENC, digest)


def dec(c, digest):
    c.cmd(OP_DEC, digest)


def probe(host, port):
    c = Conn(host, port)
    print("TLS:", c.s.version(), c.s.cipher())
    c.cmd(b"\xde\xad\xbe\xef")
    print("unknown-op reply:", c.recv(16))
    c.close()


def demo(host, port):
    """Full add -> get -> edit -> get round trip on one connection."""
    c = Conn(host, port)
    name, key, data = b"A" * 16, b"B" * 16, b"hello-world-1234"
    d = add(c, name, key, data)
    print("md5(data) =", d.hex())
    print("get ->", get(c, d, len(data) + 8))
    d2 = edit(c, d, b"second-version!!")
    print("get2 ->", get(c, d2, 24))
    c.close()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "demo"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 1443
    {"probe": probe, "demo": demo}[mode](host, port)
