import socket, concurrent.futures as cf
host,port='<target>',32783
cmds=['help','?','read','dump','mem','peek','get','ver','version','info','id','diag','dbg','shell','boot','load','upgrade','update','flash','fw','status','regs','reg','md','mrd','r','x','b','d','ls','hello','hi','NL-BCM','BCM','AT','+++','sys','test']
args=['',' 0',' 0 0',' 08000000',' 0x08000000',' 08000000 100',' 0x08000000 0x100',' a',' boot']
terms=['\n','\r','\r\n','\x00']
cases=[]
for c in cmds:
    for t in terms[:2]:
        cases.append((c+t).encode())
for c in ['read','dump','md','mrd','r','x','mem','peek','get']:
    for a in args[1:]:
        cases.append((c+a+'\r\n').encode())
def trial(b):
    try:
        s=socket.create_connection((host,port),timeout=4)
    except Exception: return None
    s.settimeout(0.7); buf=b''
    try:
        s.sendall(b)
        while True:
            d=s.recv(4096)
            if not d: break
            buf+=d
    except Exception: pass
    s.close()
    return (b,buf[:200]) if buf else None
hits=0
with cf.ThreadPoolExecutor(40) as ex:
    for r in ex.map(trial,cases):
        if r: print('HIT',r); hits+=1
print('done', len(cases),'hits',hits)
