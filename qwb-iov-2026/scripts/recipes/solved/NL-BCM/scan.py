import socket, concurrent.futures as cf
host='<target>'
ports=list(range(32700,32850))+[22,80,443,8080,8000,5555,1337,31337,9001,4444,1883,502,102,161,1234]
def chk(p):
    try:
        s=socket.create_connection((host,p),timeout=2); s.close(); return p
    except Exception: return None
with cf.ThreadPoolExecutor(50) as ex:
    res=[r for r in ex.map(chk,ports) if r]
print('open:',res)
