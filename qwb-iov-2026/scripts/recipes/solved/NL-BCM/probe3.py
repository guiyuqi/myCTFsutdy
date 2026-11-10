import socket,time,struct
host,port='<target>',32783
def trial(label, data, wait=1.5):
    try:
        s=socket.create_connection((host,port),timeout=6)
    except Exception as e:
        return (label,'CONNERR '+str(e))
    s.settimeout(wait); buf=b''
    try:
        if data: s.sendall(data)
        while True:
            d=s.recv(8192)
            if not d: break
            buf+=d
    except socket.timeout: pass
    except Exception as e: buf+=b'<'+str(e).encode()+b'>'
    s.close()
    return (label, buf[:400])
trials={
 'FWPK_hdr': open('attachment/BCM_UPDATE.fwpk','rb').read()[:32],
 'magic13572468_LE': struct.pack('<I',0x13572468),
 'magic13572468_BE': struct.pack('>I',0x13572468),
 'magic_eeadd93e': struct.pack('<I',0xeeadd93e),
 'u55aa': bytes.fromhex('55aa'),
 'u55': bytes.fromhex('55'),
 'u7f': bytes.fromhex('7f'),
 'zeros4': b'\x00'*4,
 'zeros16': b'\x00'*16,
 'ff16': b'\xff'*16,
 b'fw\n': b'fw\n',
 'u0000000000': b'\x00'*1,
}
for k,v in trials.items():
    print(trial(k,v))
