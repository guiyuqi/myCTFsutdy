import socket, concurrent.futures as cf
host,port='<target>',32783
def trial(b):
    try:
        s=socket.create_connection((host,port),timeout=4)
    except Exception: return None
    s.settimeout(0.6); buf=b''
    try:
        s.sendall(b)
        while True:
            d=s.recv(4096)
            if not d: break
            buf+=d
    except Exception: pass
    s.close()
    return (b,buf[:200]) if buf else None
with cf.ThreadPoolExecutor(40) as ex:
    for r in ex.map(trial,[bytes([i]) for i in range(256)]):
        if r: print('HIT',r)
print('done single-byte')
