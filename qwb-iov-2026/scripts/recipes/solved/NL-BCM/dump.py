from uds import *
import sys, json, os
def read_mem(c, addr, size):
    req=bytes([0x23,0x44])+addr.to_bytes(4,'big')+size.to_bytes(4,'big')
    r=c.diag(req, wait=2.0)
    if not r: return None, 'noreply'
    data=r[2]
    if data[:1]==b'\x63':
        return data[1:], None
    return None, data.hex()
if __name__=='__main__':
    addr=int(sys.argv[1],0); size=int(sys.argv[2],0); out=sys.argv[3]
    c=Conn(); print('route', c.route())
    buf=bytearray(); step=0xF0
    cur=addr
    while len(buf)<size:
        n=min(step, size-len(buf))
        d,err=read_mem(c,cur,n)
        if d is None:
            print('fail at', hex(cur), 'err', err); break
        if len(d)!=n:
            print('short', hex(cur), len(d))
        buf+=d; cur+=len(d)
        if len(buf)%0xF00==0: print(hex(addr+len(buf)), flush=True)
    open(out,'wb').write(buf)
    print('wrote', len(buf), 'bytes to', out)
