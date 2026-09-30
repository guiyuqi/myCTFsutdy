#!/usr/bin/env python3
"""
33 - ez_traffic  (Misc / 流量分析)  solver
================================================
离线题，无容器。附件: firmware/33_ez_traffic/ez_traffic.zip -> ez_traffic/ez_traffic/traffic_http.pcap

环境里没有 tshark / scapy，所以本脚本自带一个极简 pcap 解析器
（读 pcap 头 -> 逐包解析 Ethernet/IPv4/TCP -> 按四元组重组流 -> 抽 HTTP body）。

思路:
  1. 解析 pcap，重组 TCP 流。
  2. 枚举全部 HTTP 请求。绝大多数是 decoy（health.txt / site.css / readme.txt ...）。
  3. 真正的载荷: GET /download/secret.zip  ->  PK zip，单条目 secret.txt，deflate(无加密)。
  4. 解出 secret.txt = base64 字符串 -> base64 decode -> flag。
  5. 干扰流: 10.10.10.80:9001 自定义 "TELEMETRY/1.0" 协议，正文写着
     `note=payload-is-not-http`，把人往"非 HTTP 载荷"方向带（诱饵）。

用法:
  python3 scripts/33-solve.py                # 用默认附件路径
  python3 scripts/33-solve.py <path.pcap>
"""
import base64
import collections
import glob
import os
import struct
import sys
import zlib

DEFAULT_GLOBS = [
    "firmware/33_ez_traffic/**/*.pcap",
    "work/33_ez_traffic/**/*.pcap",
]


# ---------------------------------------------------------------- pcap reader
def read_pcap(path):
    """返回 (linktype, [(ts, raw_packet), ...])。支持 us/ns、大小端。"""
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian, nano = "<", False
    elif magic == 0xd4c3b2a1:
        endian, nano = ">", False
    elif magic == 0xa1b23c4d:
        endian, nano = "<", True
    elif magic == 0x4d3cb2a1:
        endian, nano = ">", True
    else:
        raise ValueError("not a pcap (magic=%08x)" % magic)

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(data):
        ts_s, ts_frac, cap, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkts.append((ts_s + ts_frac / (1e9 if nano else 1e6), data[off:off + cap]))
        off += cap
    return linktype, pkts


def parse_ipv4(pkt, linktype):
    """返回 ('tcp', src, dst, sport, dport, seq, ack, flags, payload) 或 None。"""
    if linktype == 1:                                   # Ethernet
        if len(pkt) < 14:
            return None
        eth_type = struct.unpack(">H", pkt[12:14])[0]
        payload = pkt[14:]
        if eth_type == 0x8100:                          # 802.1Q
            eth_type = struct.unpack(">H", payload[2:4])[0]
            payload = payload[4:]
        if eth_type != 0x0800:
            return None
    elif linktype == 101:                               # raw IP
        payload = pkt
    else:
        return None

    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0xF) * 4
    if payload[9] != 6 or len(payload) < ihl + 20:       # 只要 TCP
        return None
    sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", payload[ihl:ihl + 14])
    data_off = (off_flags >> 12) * 4
    return ("tcp",
            ".".join(map(str, payload[12:16])),
            ".".join(map(str, payload[16:20])),
            sport, dport, seq, ack, off_flags & 0x1FF,
            payload[ihl + data_off:])


def reassemble(path):
    """按规范四元组重组 TCP 双向流，返回 [(key, {dir_key: bytes}), ...]。"""
    linktype, pkts = read_pcap(path)
    streams = collections.OrderedDict()
    for _ts, pkt in pkts:
        r = parse_ipv4(pkt, linktype)
        if not r:
            continue
        _k, src, dst, sp, dp, seq, _ack, _fl, data = r
        key = tuple(sorted([(src, sp), (dst, dp)]))
        segs = streams.setdefault(key, collections.defaultdict(list))
        if data:
            segs[(src, sp)].append((seq, data))

    out = []
    for key, segs in streams.items():
        dirs = collections.OrderedDict()
        for d, chunks in segs.items():
            # 按 seq 排序后拼接（本 pcap 无重传/乱序，够用；有重叠时按 seq 去重）
            chunks.sort(key=lambda x: x[0])
            buf, next_seq = b"", None
            for s, c in chunks:
                if next_seq is not None and s < next_seq:
                    c = c[next_seq - s:]
                    s = next_seq
                if not c:
                    continue
                buf += c
                next_seq = s + len(c)
            dirs[d] = buf
        out.append((key, dirs))
    return out


# --------------------------------------------------------------------- HTTP
def http_pairs(streams):
    """从每个流里抽出 HTTP 请求行 + 响应 body（本 pcap 一请求一连接）。"""
    results = []
    for key, dirs in streams:
        req = next((b for b in dirs.values() if b.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD "))), None)
        rsp = next((b for b in dirs.values() if b.startswith(b"HTTP/")), None)
        if req is None:
            continue
        request_line = req.split(b"\r\n", 1)[0].decode("latin-1")
        body = b""
        if rsp and b"\r\n\r\n" in rsp:
            body = rsp.split(b"\r\n\r\n", 1)[1]
        results.append((request_line, body))
    return results


# ---------------------------------------------------------------- zip entry
def first_zip_entry(data):
    """从 PK\\x03\\x04 起解出第一个（也是唯一）条目的内容。

    只处理 method=8(deflate) / 0(stored)，flags 无加密、无 data descriptor
    —— 正好覆盖本题 secret.zip。
    """
    i = data.find(b"PK\x03\x04")
    if i < 0:
        raise ValueError("no local file header")
    (_sig, _ver, flags, method, _t, _d, _crc,
     csize, usize, nlen, elen) = struct.unpack("<IHHHHHIIIHH", data[i:i + 30])
    if flags & 0x1:
        raise ValueError("entry is ZipCrypto-encrypted (flags=0x%04x)" % flags)
    name = data[i + 30:i + 30 + nlen].decode("latin-1")
    off = i + 30 + nlen + elen                       # data descriptor 时 csize 可能为 0
    raw = data[off:off + csize] if csize else data[off:]
    if method == 8:
        raw = zlib.decompressobj(-15).decompress(raw)
    elif method != 0:
        raise ValueError("unsupported method %d" % method)
    return name, raw


def solve(pcap_path):
    print("[*] pcap: %s" % pcap_path)
    streams = reassemble(pcap_path)
    pairs = http_pairs(streams)
    print("[*] TCP streams=%d, HTTP requests=%d" % (len(streams), len(pairs)))

    for rl, body in pairs:
        print("      %-34s -> %3d bytes" % (rl, len(body)))

    # 非 HTTP 的自定义协议流也打出来（本题是诱饵）
    for key, dirs in streams:
        for d, blob in dirs.items():
            if blob and not blob.startswith((b"GET ", b"POST ", b"HTTP/")):
                print("[!] non-HTTP stream %s:%d: %r" % (d[0], d[1], blob[:120]))

    # 找 payload
    flag = None
    for rl, body in pairs:
        if body[:2] != b"PK":
            continue
        name, content = first_zip_entry(body)
        print("[+] zip entry %r (from %s): %r" % (name, rl, content))
        try:
            text = content.decode("ascii").strip()
            decoded = base64.b64decode(text, validate=True).decode("utf-8", "replace")
            print("[+] base64(%s) = %s" % (text, decoded))
            if "Game{" in decoded or "flag{" in decoded:
                flag = decoded
        except Exception as e:                       # noqa: BLE001
            print("[-] decode failed: %s" % e)
    return flag


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        cands = []
        for pat in DEFAULT_GLOBS:
            cands += glob.glob(pat, recursive=True)
        if not cands:
            print("no pcap found; run: unzip firmware/33_ez_traffic/ez_traffic.zip -d work/33_ez_traffic")
            return 1
        path = sorted(cands)[0]

    flag = solve(path)
    print()
    if flag:
        print("FLAG: %s" % flag)
        return 0
    print("FLAG: NONE")
    return 1


if __name__ == "__main__":
    sys.exit(main())
