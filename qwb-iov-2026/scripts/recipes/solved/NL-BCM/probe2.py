import socket, time
host,port='<target>',32783
def trial(data, wait=2.0, label=''):
    try:
        s=socket.create_connection((host,port),timeout=8)
    except Exception as e:
        print(label,'conn err',e); return
    s.settimeout(wait)
    if data: s.sendall(data)
    buf=b''
    try:
        while True:
            d=s.recv(8192)
            if not d: print(label,'[EOF]'); break
            buf+=d
    except socket.timeout:
        pass
    except Exception as e:
        print(label,'recv err',e)
    print(label, 'sent=',data, 'got=',repr(buf[:600]))
    s.close()

for lab,d in [('newline',b'\n'),('cr',b'\r'),('hello',b'hello\n'),('q',b'?\n'),('at',b'@\n'),('help',b'help\n'),('hexid',b'22 F1 90\n'),('uds3e',bytes([0x3e,0x00])),('id',b'I\n'),('ver',b'V\n')]:
    trial(d, 1.5, lab)
