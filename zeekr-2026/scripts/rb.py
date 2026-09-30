"""robust, retrying, chunked pipelined prober"""
import sys, os
sys.path.insert(0,'.')
from pc import *

def batch(payloads, chunk=128, retries=4, timeout=20):
    """payloads: list of raw request payloads. returns list of response bodies (or None)."""
    res=[None]*len(payloads)
    todo=list(range(len(payloads)))
    for _ in range(retries):
        if not todo: break
        nxt=[]
        for st in range(0,len(todo),chunk):
            idxs=todo[st:st+chunk]
            try:
                s=conn(timeout=timeout)
                s.sendall(b''.join(frame(payloads[i]) for i in idxs))
                got=[]
                ok=True
                for _ in idxs:
                    ln,b=recv_frame(s,timeout)
                    if ln is None: ok=False; break
                    got.append(b)
                s.close()
                if not ok or len(got)!=len(idxs):
                    nxt.extend(idxs); continue
                for i,b in zip(idxs,got): res[i]=b
            except Exception:
                nxt.extend(idxs)
        todo=nxt
    return res

def op2(tails_list):
    return batch([b'\x02'+t for t in tails_list])

def op3(args_list):
    return batch([b'\x03'+a for a in args_list])

def op1_many(n):
    s=conn(); out=[]
    for _ in range(n):
        s.sendall(frame(b'\x01')); ln,b=recv_frame(s); out.append(b[1:])
    s.close(); return out

def accept(r): return r==b'\x00\x01'
