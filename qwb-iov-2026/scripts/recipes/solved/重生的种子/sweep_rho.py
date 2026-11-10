import sys, struct, hashlib, random, itertools
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as K
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])
rhos={}
for ts,slot,ek in slots: rhos[slot]=ek[1152:]
rho_set={v:k for k,v in rhos.items()}
def G(x):
    return hashlib.sha3_512(x).digest()
def chk(d, label, slot=None):
    r,s = G(d+bytes([K.k]))[:32], G(d+bytes([K.k]))[32:]
    if r in rho_set:
        print("RHO HIT", label, "slot", rho_set[r], "d=", d.hex())
        return True
    return False

# per-slot candidate d sweep
cnt=0
for ts,slot,ek in slots:
    t4b=struct.pack('>I',ts); t4l=struct.pack('<I',ts)
    base = {
      'zero':bytes(32), '11':bytes([0x11])*32, 'range':bytes(range(32)), 'ff':b'\xff'*32,
      'ts_be_rep':t4b*8, 'ts_le_rep':t4l*8, 'ts_be_padL':t4b.ljust(32,b'\0'), 'ts_be_padR':t4b.rjust(32,b'\0'),
      'ts_le_padL':t4l.ljust(32,b'\0'), 'ts_le_padR':t4l.rjust(32,b'\0'),
      'ts_ascii_pad':str(ts).encode().ljust(32,b'\0'), 'ts_hex_pad':('%08x'%ts).encode().ljust(32,b'\0'),
      'slot_rep':bytes([slot])*32, 'slot_pad':bytes([slot])+bytes(31),
      'tag_rep':b'BCM-A3'+bytes(26), 'prod':b'BCM-A3'.ljust(32,b'\0'),
    }
    prefixes=[b'', b'BCM-A3', b'BCM-DIAG-KDF-v1', b'BCM-DIAG-PAYLOAD', b'BCM/DIAG/ACK/v1', b'bcm-prov', b'bcm', b'd', b'keygen', b'seed']
    cands=dict(base)
    for nm,b in base.items():
        for hname,h in (('sha256',hashlib.sha256),('sha3',hashlib.sha3_256),('sha3_512',lambda x: hashlib.sha3_512(x)),('b2s',hashlib.blake2s),('b2b',hashlib.blake2b)):
            cands[hname+'_'+nm]=h(b).digest()[:32]
        for p in prefixes:
            for hname,h in (('sha256',hashlib.sha256),('sha3',hashlib.sha3_256),('b2s',hashlib.blake2s)):
                cands[f'{hname}_{p.decode()}_{nm}']=h(p+b).digest()
        for p in prefixes:
            cands[f'raw_{p.decode()}_{nm}']=(p+b)[:32].ljust(32,b'\0')
    for nm,d in cands.items():
        cnt+=1
        if chk(d, f'slot{slot}:{nm}', slot): pass
print("per-slot cands tested", cnt)
