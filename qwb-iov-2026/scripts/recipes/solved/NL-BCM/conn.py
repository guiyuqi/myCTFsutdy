import socket, struct, time
HOST, PORT = '<target>', 32783

def hdr(pt, payload, ver=0x02):
    return bytes([ver, 0xFF ^ ver]) + struct.pack('>H', pt) + struct.pack('>I', len(payload)) + payload

class Conn:
    def __init__(self, host=HOST, port=PORT, timeout=6.0, ta=0x00E1, sa=0x0E00):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''
        self.sa, self.ta = sa, ta
    def send_frame(self, pt, payload):
        self.s.sendall(hdr(pt, payload))
    def recv_exact(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d: raise EOFError('closed')
            self.buf += d
        r, self.buf = self.buf[:n], self.buf[n:]
        return r
    def recv_frame(self, timeout=None):
        if timeout is not None: self.s.settimeout(timeout)
        h = self.recv_exact(8)
        ver, nver, pt, ln = struct.unpack('>BBHI', h)
        pl = self.recv_exact(ln) if ln else b''
        return pt, pl
    def route(self, sa=0x0E00, act=0x00, oem=0):
        self.send_frame(0x0005, struct.pack('>HBBI', sa, act, oem, 0))
        return self.recv_frame(3.0)
    def diag(self, uds, wait=3.0):
        self.send_frame(0x8001, struct.pack('>HH', self.sa, self.ta) + uds)
        t0 = time.time()
        while True:
            try:
                pt, pl = self.recv_frame(wait)
            except socket.timeout:
                return None
            if pt == 0x8001:
                return pl[4:]
            if time.time() - t0 > wait * 3:
                return None
