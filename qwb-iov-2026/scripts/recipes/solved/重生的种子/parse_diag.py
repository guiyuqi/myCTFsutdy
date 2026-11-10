import struct, json, sys
d = open(sys.argv[1] if len(sys.argv)>1 else 'work/ext_etc_bcm_diag.bin','rb').read()
assert d[:8]==b'BCMDIAG1'
ver, flags, count, hdr = struct.unpack('<IIII', d[8:24])
print('ver',ver,'flags',flags,'count',count,'hdr',hex(hdr))
recs={}
for i in range(count):
    off = hdr + i*0x20
    rid,roff,rlen = struct.unpack('<III', d[off:off+12])
    name = d[off+12:off+28]
    print('rec',rid,roff,rlen,name)
    recs[rid]=d[roff:roff+rlen]
kl = recs[1]; hs = recs[2]; pl = recs[3]; cf = recs[4]
print('keylog magic', kl[:8], 'count', struct.unpack('>I', kl[8:12])[0])
# slots
slots=[]
p=12
n=struct.unpack('>I', kl[8:12])[0]
for i in range(n):
    ts = struct.unpack('>I', kl[p:p+4])[0]; slot=kl[p+4]; eklen=struct.unpack('>H', kl[p+5:p+7])[0]
    ek = kl[p+7:p+7+eklen]
    slots.append((ts,slot,ek))
    p += 7+eklen
print('parsed', len(slots), 'end at', p, 'len', len(kl))
hsmagic=hs[:8]; hsn=struct.unpack('<I',hs[8:12])[0]
print('hs magic',hsmagic,'n',hsn)
hslots=[]
p=12
for i in range(hsn):
    slot=hs[p]; ctlen=struct.unpack('<I',hs[p+4:p+8])[0]; ct=hs[p+8:p+8+ctlen]
    q=p+8+ctlen
    taglen=struct.unpack('<I',hs[q:q+4])[0]; tag=hs[q+4:q+4+taglen]
    hslots.append((slot,ct,tag))
    p=q+4+taglen
print('hs parsed',len(hslots),'end',p,'len',len(hs))
print('payload', pl.hex())
print('config:'); print(cf.decode())
# per-slot ek 12-bit stats
for (ts,slot,ek) in slots:
    tpart = ek[:1152]; rho = ek[1152:]
    # unpack 12-bit little-endian pairs
    vals=[]
    for i in range(0,1152,3):
        b0,b1,b2 = tpart[i],tpart[i+1],tpart[i+2]
        vals.append(b0 | ((b1&0xF)<<8))
        vals.append((b1>>4) | (b2<<4))
    assert len(vals)==768
    print(f'slot {slot:2d} ts={ts:x} max={max(vals)} min={min(vals)} frac>3328={sum(v>3328 for v in vals)/768:.3f} rho={rho.hex()[:16]}')
import pickle
pickle.dump({'slots':slots,'hslots':hslots,'payload':pl,'config':cf}, open('work/diag.pkl','wb'))
