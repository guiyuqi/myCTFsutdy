#!/usr/bin/env python3
"""CTF solve: minimal binary protocol + CBC padding oracle -> forge role=admin -> flag.

Protocol (recovered by interaction):
  frame = uint32 BE length || payload ;  payload[0] = opcode
  op=1  -> 00 || 48B token = IV(16) || C1(16) || C2(16)   (AES-CBC, PKCS#7)
  op=2  -> 00 || byte : CBC padding oracle over last 32 bytes of arg
                        (arg length must be a multiple of 16)
  op=3  -> 00 || flag  if the *same-connection* token decrypts to "role=admin..."
           01 || "denied" otherwise
"""
import sys, binascii
sys.path.insert(0,'.')
from oracle import *          # op1_raw / pad_attack / batch
from pc import conn, frame, recv_frame

def main():
    # 1) issue a token on a connection we keep open (token is connection-bound)
    s = conn(timeout=60)
    s.sendall(frame(b'\x01')); ln, body = recv_frame(s, 30)
    o = body[1:]
    IV, C1, C2 = o[0:16], o[16:32], o[32:48]
    print(f'[*] token  = {o.hex()}')

    # 2) decrypt it with the padding oracle
    D2 = pad_attack(C2); P2 = bytes(a ^ b for a, b in zip(D2, C1))
    D1 = pad_attack(C1); P1 = bytes(a ^ b for a, b in zip(D1, IV))
    print(f'[*] plaintext = {P1 + P2!r}')

    # 3) forge "role=admin" by flipping the IV (CBC bit-flipping)
    newP1 = b'role=admin' + b' ' * 6
    IVp = bytes(a ^ b for a, b in zip(D1, newP1))
    forged = IVp + C1 + C2

    # 4) present it on the SAME connection
    s.sendall(frame(b'\x03' + forged)); ln, r = recv_frame(s, 10)
    s.close()
    print(f'[*] op3 resp = {r.hex() if r else None}')
    if r and r[0] == 0:
        print(f'[+] FLAG = {r[1:].decode()}')

if __name__ == '__main__':
    main()
