import struct,hashlib
exec(open('shared/t1.py').read().split("for (ts,slot,ek) in slots:\n    rho=")[0])
for ts,slot,ek in slots:
    ct=[c for s,c,t in hslots if s==slot][0]
    tag=[t for s,c,t in hslots if s==slot][0]
    print(f'slot {slot:2d} ct={ct.hex()}')
    print(f'        tag={tag.hex()} tagprint={tag[:8].hex()}')
print('slots keylog',[s for _,s,_ in slots])
print('slots hs',[s for s,_,_ in hslots])
