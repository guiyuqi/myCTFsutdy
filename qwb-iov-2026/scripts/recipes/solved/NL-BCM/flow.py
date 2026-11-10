import struct, emu
from conn import Conn

VIN = b'NLBC1FA704F42700B'   # confirmed by 22 F190

def main():
    fw = emu.Fw()
    c = Conn()
    print('route:', c.route())

    def uds(b, w=4.0, tag=''):
        r = c.diag(b, w)
        print('%-28s %-40s -> %s' % (tag, b.hex(), r.hex() if r else None), flush=True)
        return r

    r = uds(bytes([0x22, 0xF1, 0x90]), tag='VIN')
    assert r and r[:3] == b'\x62\xf1\x90' and r[3:] == VIN, 'VIN mismatch'

    assert uds(bytes([0x10, 0x03]), tag='10 03')[:1] == b'\x50'
    assert uds(bytes([0x10, 0x02]), tag='10 02')[:1] == b'\x50'

    r = uds(bytes([0x27, 0x01]), tag='27 01')
    assert r and r[0] == 0x67
    seed = struct.unpack('<I', r[2:6])[0]
    k1 = fw.key1(seed)
    print('   seed=%08x key1=%08x' % (seed, k1))
    r = uds(bytes([0x27, 0x02]) + struct.pack('<I', k1), tag='27 02')
    assert r and r == b'\x67\x02'

    r = uds(bytes([0x27, 0x03]), tag='27 03')
    assert r and r[0] == 0x67
    s1, s2 = struct.unpack('<II', r[2:10])
    lo, hi = fw.key2(s1, s2)
    print('   seeds=%08x %08x keys=%08x %08x' % (s1, s2, lo, hi))
    r = uds(bytes([0x27, 0x04]) + struct.pack('<II', lo, hi), tag='27 04')
    assert r and r == b'\x67\x04'

    addr = 0x0801C000
    ln = 0x100
    r = uds(bytes([0x31, 0x01, 0xFF, 0x00]) + struct.pack('>II', addr, ln), tag='31 01 FF00 erase')
    assert r and r[0] == 0x71, r

    r = uds(bytes([0x34, 0x00, 0x44]) + struct.pack('>II', addr, ln), tag='34 request download')
    assert r and r[0] == 0x74, r

    calib = open('calib.bin', 'rb').read()
    seq = 1
    for i in range(0, 256, 64):
        chunk = calib[i:i+64]
        r = uds(bytes([0x36, seq]) + chunk, tag='36 block %d' % seq)
        assert r and r[0] == 0x76, r
        seq += 1
    r = uds(bytes([0x37]), tag='37 transfer exit')
    assert r and r[0] == 0x77, r

    r = uds(bytes([0x31, 0x01, 0x02, 0x02]), tag='31 01 0202 checksum')
    assert r and r[0] == 0x71 and r[-1] == 0, r

    r = uds(bytes([0x31, 0x01, 0x02, 0x03]), tag='31 01 0203 dependency')
    assert r and r[0] == 0x71 and r[-1] == 0, r

    proof = fw.proof(calib)
    print('   proof=%08x' % proof)
    r = uds(bytes([0x31, 0x01, 0x02, 0x04]) + struct.pack('<I', proof), tag='31 01 0204 prove')
    assert r and r[0] == 0x71 and r[-1] == 0, r

    r = uds(bytes([0x22, 0xFD, 0x10]), w=6.0, tag='22 FD10 RESULT')
    if r:
        print('RESULT BYTES:', r)
        print('RESULT ASCII:', r[3:])

if __name__ == '__main__':
    main()
