import hmac,hashlib,glob,os,sys
from concurrent.futures import ThreadPoolExecutor
W='~/.ctfagent/state/sessions/winews/workspace/'
bundle=open(W+'recovery.bundle','rb').read()
target=bundle[36:68]; msg=b'LI7/tag\x00'+bundle[0:36]+bundle[0x44:]
cands=[];seen=set()
for fn in sorted(glob.glob(W+'vm*.bin')):
    d=open(fn,'rb').read()
    for i in range(len(d)-31):
        k=d[i:i+32]
        if k in seen: continue
        seen.add(k); cands.append((os.path.basename(fn),i,k))
print('cands',len(cands),flush=True)
def t(x):
    f,i,k=x
    if hmac.new(k,msg,hashlib.sha256).digest()==target: return (f,i,k)
with ThreadPoolExecutor(max_workers=16) as ex:
    for r in ex.map(t,cands,chunksize=64):
        if r: print('HIT',r[0],hex(r[1]),r[2].hex(),flush=True)
print('done',flush=True)
