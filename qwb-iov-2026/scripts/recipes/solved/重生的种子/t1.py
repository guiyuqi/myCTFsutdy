import sys, struct, hashlib
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
d=open('work/ext_etc_bcm_diag.bin','rb').read()
recs={}
ver,flags,count,hdr=struct.unpack('<IIII',d[8:24])
for i in range(count):
    o=hdr+i*0x20; rid,roff,rlen=struct.unpack('<III',d[o:o+12]); recs[rid]=d[roff:roff+rlen]
kl=recs[1]; hs=recs[2]
n=struct.unpack('>I',kl[8:12])[0]; p=12; slots=[]
for i in range(n):
    ts=struct.unpack('>I',kl[p:p+4])[0]; slot=kl[p+4]; ekl=struct.unpack('>H',kl[p+5:p+7])[0]
    slots.append((ts,slot,kl[p+7:p+7+ekl])); p+=7+ekl
hn=struct.unpack('<I',hs[8:12])[0]; p=12; hslots=[]
for i in range(hn):
    slot=hs[p]; cl=struct.unpack('<I',hs[p+4:p+8])[0]; ct=hs[p+8:p+8+cl]; q=p+8+cl
    tl=struct.unpack('<I',hs[q:q+4])[0]; tag=hs[q+4:q+4+tl]
    hslots.append((slot,ct,tag)); p=q+4+tl

def unpack_raw12(b):
    v=[]
    for i in range(0,len(b),3):
        b0,b1,b2=b[i],b[i+1],b[i+2]
        v.append(b0|((b1&0xF)<<8)); v.append((b1>>4)|(b2<<4))
    return v
def compress(x,dd):
    return (((x<<dd)+K.R.q//2)//K.R.q)%(1<<dd)
def pack12_std(vals):
    # FIPS ByteEncode12: bit stream little endian
    bits=0; nbits=0; out=bytearray()
    for v in vals:
        bits |= (v&0xFFF)<<nbits; nbits+=12
        while nbits>=8:
            out.append(bits&0xFF); bits>>=8; nbits-=8
    return bytes(out)

def our_ek_to_std(ek):
    t=unpack_raw12(ek[:1152]); rho=ek[1152:]
    tc=t
    return pack12_std(tc)+rho

def cands(ts,slot,ek):
    out={}
    t4b=struct.pack('>I',ts); t4l=struct.pack('<I',ts)
    out['zero32']=bytes(32)
    out['11x32']=bytes([0x11])*32
    out['rang32']=bytes(range(32))
    out['ts_be_rep']=(t4b*8)[:32]
    out['ts_le_rep']=(t4l*8)[:32]
    out['ts_be_pad']=t4b.rjust(32,b'\x00')
    out['ts_le_pad']=t4l.rjust(32,b'\x00')
    out['ts_be_padL']=t4b.ljust(32,b'\x00')
    out['sha256_be']=hashlib.sha256(t4b).digest()
    out['sha3_be']=hashlib.sha3_256(t4b).digest()
    out['sha3_512_be']=hashlib.sha3_512(t4b).digest()[:32]
    out['sha256_ascii']=hashlib.sha256(str(ts).encode()).digest()
    out['slot32']=bytes([slot])*32
    out['idx_be_rep']=struct.pack('>I',slot)*8
    out['ts_BcdBytes']=bytes([0x20,0x26,0x07,0x14+slot])*8
    return out

for (ts,slot,ek) in slots:
    rho=ek[1152:]
    c=cands(ts,slot,ek)
    for name,dd in c.items():
        # keygen: rho = G(d+k)[:32]
        rho2,sig=K._G(dd+bytes([K.k]))
        if rho2==rho:
            print("RHO MATCH",slot,name,dd.hex())
print("rho test done")
# test encaps for candidate m
for (ts,slot,ek) in slots:
    stdek=our_ek_to_std(ek)
    # validate via kyber decode
    try:
        K._k_pke_encrypt(stdek, bytes(32), bytes(32))
    except Exception as e:
        print('slot',slot,'ek construct err',e); continue
    ms={'zero':bytes(32),'11':bytes([0x11])*32}
    for nm,m in ms.items():
        try:
            ct=K._k_pke_encrypt(stdek,m,bytes(32))
        except Exception as e:
            print('enc err',e); continue
        # find hs
        for (hslot,ct2,tag) in hslots:
            if hslot==slot and ct2==ct:
                print("CT MATCH m=",nm,"slot",slot)
print("enc test done")
