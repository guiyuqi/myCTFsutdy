import socket, struct, time

HOST = '<target>'
PORT = 33221

def conn(timeout=6):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((HOST, PORT))
    return s

def frame(payload):
    return struct.pack('>I', len(payload)) + payload

def recvn(s, n, timeout=4.0):
    s.settimeout(timeout)
    buf = b''
    while len(buf) < n:
        try:
            c = s.recv(n - len(buf))
        except socket.timeout:
            return None
        if not c:
            return None
        buf += c
    return buf

def recv_frame(s, timeout=4.0):
    hdr = recvn(s, 4, timeout)
    if hdr is None:
        return None, None
    ln = struct.unpack('>I', hdr)[0]
    if ln > 1 << 20:
        return ln, ('BADLEN', hdr)
    body = recvn(s, ln, timeout) if ln else b''
    return ln, body

def rt(payloads, timeout=4.0, keep=True):
    """send payloads in one session, return list of (len, body); keep=False on error"""
    s = conn()
    out = []
    try:
        for p in payloads:
            s.sendall(frame(p))
            ln, b = recv_frame(s, timeout)
            out.append((ln, b))
            if ln is None:
                break
    finally:
        s.close()
    return out
