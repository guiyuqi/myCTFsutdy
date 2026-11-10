import socket, concurrent.futures as cf
host='<target>'
ports=[32783,32785,32786,32787,32789,32791,32793,32794,32797,32798,32801,32804,32805,32806,32807,32809,32810,32811,32814,32815,32817,32818,32819,32820,32824,32825,32826,32827,32828,32829,32830,32833,32835,32837,32838,32839,32841,32842,32843,32844,32845,32849]
def chk(p):
    try:
        s=socket.create_connection((host,p),timeout=4)
    except Exception as e: return (p,'conn '+repr(e))
    s.settimeout(1.5); buf=b''
    try:
        while True:
            d=s.recv(4096)
            if not d: break
            buf+=d
            if len(buf)>800: break
    except Exception: pass
    s.close(); return (p,buf[:200])
with cf.ThreadPoolExecutor(20) as ex:
    for p,b in ex.map(chk,ports):
        print(p, repr(b))
