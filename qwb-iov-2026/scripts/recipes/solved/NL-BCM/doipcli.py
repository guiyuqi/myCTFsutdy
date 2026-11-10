import socket, struct, time

HOST, PORT = '<target>', 32783

def frame(pt, payload):
    return bytes([0x02, 0xFD]) + struct.pack('>HI', pt, len(payload)) + payload

class DoIP:
    def __init__(self, host=HOST, port=PORT, timeout=5.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''
        self.sa = 0x0E00
        self.ta = 0x00E1

    def send(self, pt, payload):
        self.s.sendall(frame(pt, payload))

    def recv_frame(self, timeout=5.0):
        self.s.settimeout(timeout)
        while True:
            if len(self.buf) >= 8:
                ver, inv, pt, ln = struct.unpack('>BBHI', self.buf[:8])
                if len(self.buf) >= 8 + ln:
                    pl = self.buf[8:8+ln]
                    self.buf = self.buf[8+ln:]
                    return ver, pt, pl
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                return None
            if not d:
                return None
            self.buf += d

    def route(self):
        p = struct.pack('>HBB I', self.sa, 0x00, 0x00, 0)
        self.send(0x0005, p)
        r = self.recv_frame()
        return r

    def uds(self, data, timeout=5.0):
        p = struct.pack('>HH', self.sa, self.ta) + data
        self.send(0x8001, p)
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.recv_frame(timeout=max(0.05, deadline-time.time()))
            if r is None: return None
            ver, pt, pl = r
            if pt == 0x8001:
                return pl
            # ignore other types
        return None

    def close(self):
        try: self.s.close()
        except: pass
