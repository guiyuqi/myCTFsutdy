#!/usr/bin/env python3
"""easytl: replay-based TLS1.3 ClientHello with the hardcoded external PSK.

Uses a *captured* real ClientHello (captured_ch.bin, from `openssl s_client`)
as a template, drops its pre_shared_key extension and appends ours with a
48-byte SHA-384 binder computed from the recovered PSK.

Recovered facts (verified under gdb):
  PSK (64 B) = HMAC-SHA512(key = bytes.fromhex(
        "c8ad2a35c51b87a466e22bc337696f08"   0x825060
        "07ff73500ee154ee71bee86d0b6bc358"
        "422a0e90fca2ac1be5929a7be06fd428"),  # 96 hex chars = 48 bytes
      msg = b"1401518dc5d7641ccd41593a5d812410")
  session cipher = TLS_AES_256_GCM_SHA384 -> binder hash SHA-384, binder 48 B
  (the server rejects anything else: len(binder) must be 0x30, line 1199)
"""
import hashlib
import hmac
import socket
import struct
import sys

IDENTITY = b"1401518dc5d7641ccd41593a5d812410"
HEXKEY = (b"c8ad2a35c51b87a466e22bc337696f08"
          b"07ff73500ee154ee71bee86d0b6bc358"
          b"422a0e90fca2ac1be5929a7be06fd428")


def psk():
    return hmac.new(bytes.fromhex(HEXKEY.decode()), IDENTITY, hashlib.sha512).digest()


def hkdf_extract(salt, ikm, h):
    return hmac.new(salt, ikm, h).digest()


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
    ln = int.from_bytes(ch[1:4], "big")
    body = ch[4:4 + ln]
    off = 2 + 32
    sidlen = body[off]
    off += 1 + sidlen
    cl = int.from_bytes(body[off:off + 2], "big")
    off += 2 + cl
    compl = body[off]
    off += 1 + compl
    extl = int.from_bytes(body[off:off + 2], "big")
    # prefix must stop BEFORE the extensions-length field (rebuild re-adds it)
    return body[:off], body[off + 2:off + 2 + extl]


def rebuild(ch, exts):
    prefix, _ = split_ch(ch)
    body = prefix + struct.pack("!H", len(exts)) + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body


def make(psk_bytes, template, hash_name="sha384"):
    h = getattr(hashlib, hash_name)
    hlen = h().digest_size
    _, exts = split_ch(template)
    kept = b""
    i = 0
    while i < len(exts):
        t = int.from_bytes(exts[i:i + 2], "big")
        l = int.from_bytes(exts[i + 2:i + 4], "big")
        if t != 0x0029:
            kept += exts[i:i + 4 + l]
        i += 4 + l
    identities = struct.pack("!H", len(IDENTITY)) + IDENTITY + struct.pack("!I", 0)
    binder = b"\x00" * hlen

    def assemble(b):
        psk_body = (2 + len(identities)) + (2 + 1 + len(b))
        psk_ext = struct.pack("!HH", 0x0029, psk_body) + \
            struct.pack("!H", len(identities)) + identities + \
            struct.pack("!H", 1 + len(b)) + bytes([len(b)]) + b
        return rebuild(template, kept + psk_ext)

    ch = assemble(binder)
    truncated = ch[:len(ch) - (2 + 1 + hlen)]
    early = hkdf_extract(b"\x00" * hlen, psk_bytes, h)
    # Derive-Secret(early, "ext binder", "") => context is Transcript-Hash("")
    bk = expand_label(early, b"ext binder", h(b"").digest(), hlen, h)
    fk = expand_label(bk, b"finished", b"", hlen, h)
    b = hmac.new(fk, h(truncated).digest(), h).digest()
    return assemble(b)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1443
    template = open("captured_ch.bin", "rb").read()[5:]   # strip record header
    p = psk()
    print("PSK =", p.hex())
    ch = make(p, template)
    print("CH len =", len(ch), "binder =", ch[-48:].hex())
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch)
    s.settimeout(5)
    try:
        d = s.recv(4096)
    except socket.timeout:
        d = b""
    print("resp %d B: %s" % (len(d), d[:24].hex()))
    if len(d) > 5 and d[0] == 0x16:
        print("=> HANDSHAKE record, msg type %d -> %s" %
              (d[5], "ServerHello!" if d[5] == 2 else "?"))
    elif d and d[0] == 0x15:
        print("=> ALERT level=%d desc=%d" % (d[1], d[2]))
    s.close()


if __name__ == "__main__":
    main()
