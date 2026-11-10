import hashlib, hmac, struct, re, sys, os, itertools

W = '~/.ctfagent/state/sessions/winews/workspace/'
bundle = open(W + 'recovery.bundle', 'rb').read()

TAG = bundle[0x24:0x44]
MSG = b'LI7/tag\x00' + bundle[0:0x24] + bundle[0x44:]
VIEW = b'LI7/view\x00'

def hit(cred):
    """cred: 32 bytes. Returns True if the exe's final HMAC check passes."""
    if len(cred) != 32:
        return False
    h1 = hashlib.sha256(VIEW + cred).digest()
    t = hmac.new(h1, MSG, hashlib.sha256).digest()
    return t == TAG

if __name__ == '__main__':
    # sanity: wrong cred must fail
    print('TAG', TAG.hex())
    print('zero cred ->', hit(b'\x00' * 32))
