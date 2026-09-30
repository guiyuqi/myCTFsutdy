#!/usr/bin/env python3
"""32 - 四月是你的谎言 : key recovery verification.

Service: nc nc1.ctfplus.cn 25192  (one-shot, fixed params)
Banner:
    message = YOU DID LIVE IN MY HEART
    hash(key+message) = 46af62962126aa38e4f1680a6c64bc6b
    please echo the mission in hash(key+message+response)
    new longing:

Recovered secret key:
    KEY = bytes.fromhex("2026") = b" &"      (0x20, 0x26)
    md5(KEY + message) == 46af62962126aa38e4f1680a6c64bc6b     <-- exact match

Uniqueness: exhaustive search over all 1-byte (256) and 3-byte (2^24) keys
found no other key producing the banner digest; the 2-byte search over the
full 65536 space yields exactly this one key.

Note: bytes 0x20 0x26 spelled as text is "0x2026", the same passphrase the
author used in challenge 7 ("密码是0x2026"). The key is byte-packed, not the
literal 6-char string.
"""
import hashlib

MSG = b"YOU DID LIVE IN MY HEART"
BANNER_DIGEST = "46af62962126aa38e4f1680a6c64bc6b"
KEY = bytes.fromhex("2026")


def main():
    assert hashlib.md5(KEY + MSG).hexdigest() == BANNER_DIGEST
    print("[+] KEY            =", repr(KEY), "= bytes.fromhex('2026')")
    print("[+] md5(key+message) =", hashlib.md5(KEY + MSG).hexdigest())
    print("[+] banner digest    =", BANNER_DIGEST, " -> MATCH")

    print("\n[*] md5(key+message+response) for story-mandated responses:")
    for r in [b"", b"TOO", b" TOO", b"TOO\n", b"I LOVE YOU TOO",
              b"YOU DID LIVE IN MY HEART TOO"]:
        print("    resp=%-32r %s" % (r, hashlib.md5(KEY + MSG + r).hexdigest()))


if __name__ == "__main__":
    main()
