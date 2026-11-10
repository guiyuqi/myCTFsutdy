import struct, hashlib, math
exec(open('shared/r97work/sim.py').read().split('# DFT')[0])

EXPECTX0_RAW = None
exe=open(EXE,'rb').read()
def rd(va,n):
    return exe[0x4200 + (va-0x406000): 0x4200 + (va-0x406000)+n]
EXP0=list(struct.unpack('<56I', rd(0x406540,56*4)))
EXP1=list(struct.unpack('<56I', rd(0x406460,56*4)))

md5tok=hashlib.md5(TOKEN).digest()
sha_tok=hashlib.sha256(TOKEN).digest()

# DFT bytes
dat=ch[b'data'][0]
samples=dat[0x5140:0x5140+4096]
dft=[]
for k in range(16):
    f=50+8*k
    re=0.0; im=0.0
    for i in range(4096):
        s=samples[i]-128
        ph=2*math.pi*f*i/4096.0
        re+=s*math.cos(ph); im-=s*math.sin(ph)
    dft.append(int(round(math.sqrt(re*re+im*im)*(2**-8)))&0xff)
buf810=bytes(a^b for a,b in zip(dft,md5tok))

# FNV of exe
def fnv64(b):
    h=0xcbf29ce484222325
    for c in b:
        h=((h^c)*0x100000001b3)&0xffffffffffffffff
    return h
fn=fnv64(exe)
edx=((fn>>32)^fn)&0xffffffff

S=list(struct.unpack('<5I', sha_tok[0:20]))
fold=0x9e3779b9
for i in range(0x1000):
    fold=mix32(fold^i)
s=[0]*5
s[0]=fold^S[0]
eax=0x9e3779b9
for i in range(16):
    eax=mix32(buf810[i]^eax)
s[1]=eax^S[1]
s[2],s[3],s[4]=S[2],S[3],S[4]
print('state init',[hex(x) for x in s])

A4=mix32(s[0]^s[4]); A8=mix32(s[1]^s[2]); AC=mix32((s[1]^s[2])^s[3])

groups=[(g0,8),(g1,16),(g2,32)]
idx=0
state=s[:]
notes=[]
for d,count in groups:
    for k in range(count):
        t=d[3*k+2]
        N=(mix32(((idx*0x9e3779b9)&0xffffffff)^s[4])&3)+1
        v5c=((idx*0x9e3779b9)&0xffffffff)^A4
        v68=(((idx*0x85ebca6b)&0xffffffff)^AC)^rol32(A8, idx&31)
        tgt0=mix32(v5c)^EXP0[idx]
        tgt1=mix32(v68)^EXP1[idx]
        sols=[]
        for a in range(256):
            # check r13 chain only
            r13=state[0]
            ebx=state[1]; esi=state[2]; edi=state[3]; r12=state[4]
            for it in range(N):
                r13=mix32(r13^a)
                ebx=rol32((ebx+b_)&0xffffffff,7) if False else ebx
            # placeholder
        # real search
        for a in range(256):
            ok=False
            for b in range(256):
                r13=state[0]; ebx=state[1]; esi=state[2]; edi=state[3]; r12=state[4]
                sh=(t<<(a&3))&0xffffffff
                for it in range(N):
                    r13=mix32(r13^a)
                    ebx=rol32((ebx+b)&0xffffffff,7)
                    r15=(sh^r13)&0xffffffff
                    esi=mix32(esi^ebx^t)
                    edi=rol32(edi^r13,13)
                    r12=(r12^(r15^esi))&0xffffffff
                    ebx=mix32((ebx+edi)&0xffffffff)
                if r13==tgt0 and esi==tgt1:
                    sols.append((a,b,ebx))
            if len(sols)>4: break
        print('note',idx,'t=%02x'%t,'N=',N,'sols',[(a,b,'%08x'%e) for a,b,e in sols][:6], 'n=',len(sols))
        if not sols: raise SystemExit('no sol')
        a,b,ebx=sols[0]
        notes.append((a,b))
        state[1]=ebx; state[0]=tgt0
        idx+=1
print('state final',[hex(x) for x in state])
print('notes',notes)
buf28=struct.pack('<5I',*state)+bytes([0x38,0,0,0])+struct.pack('<I',edx)
h=hashlib.sha256(buf28).digest()
key16=bytes(h[i//2] if i%2==0 else md5tok[i//2] for i in range(16))
print('key16',key16.hex())
# decrypt flgx
T=[0]*256
ab=abox
for i in range(256): T[ab[i]]=i
def dec(block,pad,key16,T):
    st=bytearray(block)
    for r in range(12):
        k=r
        # part1
        for i in range(16):
            st[i]^= ((0xa7-7*k+i)&0xff) ^ key16[(0xb+i)&0xf]
        # part2  (i=0..7 first idx 7..0)
        for i in range(8):
            p=7-i; q=(p+9)&0xf
            c=st[p]^st[q]
            st[p]=rol8(c,1)^st[p]
            st[q]=c
        # part3 k=7..0
        for kk in range(7,-1,-1):
            c=st[kk]^st[kk+8]
            st[kk]=rol8(c,1)^st[kk]
            st[kk+8]=c
        # part4
        for i in range(16):
            st[i]=T[st[i]]
    return bytes(x^y for x,y in zip(st,pad))
pad=struct.unpack('<QQ', h[16:32])
pad=h[16:32]
pt=b''
prevpad=pad
for bnum in range(3):
    ct=flgx[16*bnum:16*bnum+16]
    p=dec(ct,prevpad,key16,T)
    pt+=p
    prevpad=ct
print('pt',pt.hex())
print('pt repr',pt)
# final FNV check
fnv=fnv64(pt[:32])
tgt=((mix32(0x44d9bc7a)<<32)|mix32(0x9a4a75d6))
print('fnv',hex(fnv),'target',hex(tgt),'MATCH' if fnv==tgt else 'NOMATCH')
