import socket, sys, time
host,port='<target>',32783
s=socket.create_connection((host,port),timeout=10)
s.settimeout(4)
time.sleep(1.0)
buf=b''
try:
    while True:
        d=s.recv(4096)
        if not d: 
            print("[EOF]"); break
        buf+=d
        print(repr(d))
except socket.timeout:
    print("[timeout]")
print("total:",len(buf))
print(buf.decode('utf-8','replace'))
s.close()
