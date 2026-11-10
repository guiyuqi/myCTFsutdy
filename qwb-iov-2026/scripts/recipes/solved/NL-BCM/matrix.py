import socket, struct, time, itertools
host,port='<target>',32783
def trial(label, data, wait=1.0):
    try:
        s=socket.create_connection((host,port),timeout=5)
    except Exception as e:
        return (label,'CONNERR '+repr(e))
    s.settimeout(wait); buf=b''
    try:
        s.sendall(data)
        while True:
            d=s.recv(65536)
            if not d: break
            buf+=d
    except socket.timeout: pass
    except Exception as e: buf+=b'<ERR '+repr(e).encode()+b'>'
    s.close()
    return (label, buf[:200])
uds = {
 'readmem_ALFID': bytes.fromhex('230A08000000')+bytes.fromhex('0010'),
 'readmem':       bytes.fromhex('2308000000')+bytes.fromhex('0010'),
 'readmem_sh':     bytes.fromhex('2300')+bytes.fromhex('08000000')+bytes.fromhex('0010'),
 'rdbi_f190':      bytes.fromhex('22F190'),
 'session':        bytes.fromhex('1003'),
 'tp':             bytes.fromhex('3E00'),
}
frames={
 'raw': lambda p:p,
 'len1': lambda p:bytes([len(p)])+p,
 'len2le': lambda p:struct.pack('<H',len(p))+p,
 'len4le': lambda p:struct.pack('<I',len(p))+p,
 'isotp1': lambda p:bytes([len(p)])+p+b'\xaa'*(8-1-len(p)),
 'aa_pre': lambda p:b'\xaa'+p,
 'hexnl': lambda p:p.hex().upper().encode()+b'\n',
 'hexnl_sp': lambda p:' '.join(p.hex().upper()[i:i+2] for i in range(0,len(p.hex()),2)).encode()+b'\r\n',
}
for un,up in uds.items():
    for fn,ff in frames.items():
        lab=f'{un}/{fn}'
        r=trial(lab, ff(up), 0.8)
        if r[1]: print('HIT',r)
print('done matrix')
