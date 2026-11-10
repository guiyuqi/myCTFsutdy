import sys, struct, collections
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])
print("slots order in keylog:", [s for _,s,_ in slots])
print("hslots order:", [s for s,_,_ in hslots])
for s,ct,tag in hslots:
    print(f"slot {s:2d} ctlen {len(ct)} tag {tag.hex()}")
tags=[t for _,_,t in hslots]
print("distinct tags:", len(set(tags)))
cts=[c for _,c,_ in hslots]
print("distinct cts:", len(set(cts)))
# u/v distributions
q=3329
def decompress10(b):
    vals=[]
    for i in range(0,960,5):
        c=b[i]|(b[i+1]<<8)|(b[i+2]<<16)|(b[i+3]<<24)|(b[i+4]<<32)
        for j in range(4):
            vals.append((c>>(10*j))&1023)
    return vals
def decompress4(b):
    vals=[]
    for i in range(0,128,2):
        vals.append(b[i]&0xF); vals.append((b[i]>>4)|((b[i+1]&0xF)<<4))
    return vals
for s,ct,tag in hslots:
    u=decompress10(ct[:960]); v=decompress4(ct[960:])
    # centered values
    uc=[(x*3329+512)//1024 for x in u]
    uc=[x if x<1665 else x-3329 for x in uc]
    small=sum(1 for x in uc if abs(x)<64)
    print(f"slot {s:2d} u_near0={small:3d}/768 u_mean={sum(u)/768:6.1f} v_distinct={len(set(v))} v_mean={sum(v)/256:5.2f}")
