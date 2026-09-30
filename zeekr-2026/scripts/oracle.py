import sys, os
sys.path.insert(0,'.')
from rb import *

def op1_raw():
    s=conn(); s.sendall(frame(b'\x01')); ln,b=recv_frame(s); s.close()
    return b[1:]

def oracle_many(pairs):
    """pairs: list of (X16, T16). arg = 16 zeros + X + T (48 bytes, multiple of 16).
       server decrypts last 32 bytes (X||T) as 2-block CBC and checks PKCS#7 padding of D(T)^X."""
    args=[bytes(16)+X+T for X,T in pairs]
    rs=batch([b'\x02'+a for a in args], chunk=96)
    return [r==b'\x00\x01' for r in rs]

def oracle(X,T):
    return oracle_many([(X,T)])[0]

def pad_attack(T, log=None):
    """recover D(T) using the padding oracle"""
    D=bytearray(16)
    for i in range(15,-1,-1):
        pad=16-i
        base=bytearray(16)
        for j in range(i+1,16):
            base[j]=D[j]^pad
        # gather candidates in batches
        cands=[]
        for g in range(256):
            X=bytearray(base); X[i]=g
            cands.append(bytes(X))
        res=oracle_many([(X,T) for X in cands])
        passed=[g for g in range(256) if res[g]]
        # disambiguate: a true padding hit stays valid when we perturb an earlier byte
        chosen=None
        for g in passed:
            X=bytearray(base); X[i]=g
            probe=bytearray(X)
            # perturb a byte strictly before i (not part of padding)
            if i>0:
                probe[0]^=0xFF
            else:
                probe[1]^=0xFF   # for i=0 there is no earlier byte; skip check
            if i==0:
                chosen=g; break
            if oracle_many([(bytes(probe),T)])[0]:
                chosen=g; break
        if chosen is None:
            if passed: chosen=passed[0]
            else:
                raise RuntimeError(f'no candidate at i={i} (passed={passed})')
        D[i]=chosen^pad
        if log: log(f'   D[{i:2d}] = {D[i]:02x}  (pad={pad}, candidates={passed})')
    return bytes(D)
