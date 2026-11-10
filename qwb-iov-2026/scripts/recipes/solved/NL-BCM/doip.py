import socket, struct
host,port='<target>',32783
def doip(pt, payload, ver=2):
    return bytes([ver, 0xFF^ver])+struct.pack('>H',pt)+struct.pack('>I',len(payload))+payload
tests={
 'veh_id_req': doip(0x0001,b''),
 'veh_id_req_q': doip(0x0001,b'\x00'),
 'routing_act_default': doip(0x0005, struct.pack('>HBBI',0x0e00,0x00,0x00,0)),
 'routing_act_oem': doip(0x0005, struct.pack('>HBBI',0x0e00,0x01,0x00,0)),
 'routing_act_v1': doip(0x0005, struct.pack('>HBBI',0x0e00,0x00,0x00,0), ver=1),
 'alive': doip(0x0007, struct.pack('>H',0x0e00)),
 'diag_readmem': doip(0x8001, struct.pack('>HH',0x0e00,len(bytes.fromhex('230A08000000')+bytes.fromhex('0010')))+(bytes.fromhex('230A08000000')+bytes.fromhex('0010'))),
}
def trial(lab,data,wait=1.5):
    s=socket.create_connection((host,port),timeout=5); s.settimeout(wait); buf=b''
    try:
        s.sendall(data)
        while True:
            d=s.recv(8192)
            if not d: break
            buf+=d
    except socket.timeout: pass
    except Exception as e: buf+=b'<'+repr(e).encode()+b'>'
    s.close()
    print(lab, data.hex(), '->', repr(buf[:300]))
for k,v in tests.items(): trial(k,v)
