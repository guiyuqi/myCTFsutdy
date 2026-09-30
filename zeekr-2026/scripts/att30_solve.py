#!/usr/bin/env python3
"""attachments30.zip / "MOSAIC CARRIER MAP / REVISION 7"  (== attachments9.zip)

载体: carrier.bin = 16 个 0x200 字节页。卡片(carrier_map.png)给出的规则:

  +000..+01F  masked share (32B)
  +1E0        page id (1B)            <- 表里按十六进制显示
  +1E2        status byte  参与页 == 0x5A
  +1E4        CRC32 of +000..+1DF, big endian
  +1EC        reserved     参与页 == 0xA5

  参与条件(四条同时成立):
    status==0x5A 且 reserved==0xA5 且 CRC32 匹配 且 page id 在 mosaic 表内
  mosaic 表: 21->1, 24->2, 27->3, 2B->4, 2E->5      FAMILY = "MOSAIC-CARRIER-7"
  mask = SHA256(FAMILY || page_id || order)[0:32]
  plain share = masked share XOR mask
  manifest secret = 所有参与页 plain share 逐字节 XOR   (32 字节)

  注意: 16 页 CRC 全部合法(CRC 在本例中不筛页), 真正筛掉的是
        status / reserved / 表成员; 陷阱页 2A 满足前三项但不在表里。

平台提示已确认本链路(四重校验 + 必须先解掩码再异或, 载体里没有明文 manifest)。

卡片公式没写 page_id / order 的编码方式, 平台提示也没写, 因此这里把两条轴的
组合都算出来, 供按序提交:
  轴1 掩码输入:  raw = 单字节 (bytes([pid])/bytes([order]))   <- 首选
                 ascii = 表内文本 ("21" + "1")
  轴2 flag 取值: secret.hex()        (同批已确认题目: flag=最终物件 hex, 无二次哈希)
                 sha256(secret).hex() (备选)
"""
import binascii
import hashlib
import struct

CARRIER = "work/att30/attachments/carrier.bin"
FAMILY = b"MOSAIC-CARRIER-7"
TABLE = [(0x21, 1), (0x24, 2), (0x27, 3), (0x2B, 4), (0x2E, 5)]


def parse(path):
    data = open(path, "rb").read()
    assert len(data) == 16 * 0x200, len(data)
    pages = {}
    for i in range(16):
        p = data[i * 0x200:(i + 1) * 0x200]
        crc = struct.unpack(">I", p[0x1E4:0x1E8])[0]
        pages[p[0x1E0]] = dict(
            idx=i, page=p, share=p[0:0x20], status=p[0x1E2], reserved=p[0x1EC],
            crc_ok=(crc == (binascii.crc32(p[0:0x1E0]) & 0xFFFFFFFF)),
        )
    return pages


def masks(pid, order):
    """两种编码读法 -> (raw, ascii) 掩码"""
    raw = hashlib.sha256(FAMILY + bytes([pid, order])).digest()[:32]
    asc = hashlib.sha256(FAMILY + b"%02X" % pid + b"%d" % order).digest()[:32]
    return raw, asc


def main():
    pages = parse(CARRIER)

    print("== 16 页四重校验 ==")
    for pid in sorted(pages):
        pg = pages[pid]
        in_tab = any(p == pid for p, _ in TABLE)
        ok = pg["status"] == 0x5A and pg["reserved"] == 0xA5 and pg["crc_ok"] and in_tab
        print(f"  page{pg['idx']:2d} id={pid:02X} st={pg['status']:02X} resv={pg['reserved']:02X} "
              f"crc_ok={pg['crc_ok']} in_table={in_tab} -> {ok}")

    secrets = {}
    for label, mi in (("raw", 0), ("ascii", 1)):
        acc = bytearray(32)
        for pid, order in TABLE:
            for j in range(32):
                acc[j] ^= pages[pid]["share"][j] ^ masks(pid, order)[mi][j]
        secrets[label] = bytes(acc)

    ladder = [
        ("raw", "hex"), ("raw", "sha256"), ("ascii", "hex"), ("ascii", "sha256"),
    ]
    print("\n== 候选 flag（按建议提交顺序） ==")
    for i, (enc, how) in enumerate(ladder, 1):
        s = secrets[enc]
        payload = s.hex() if how == "hex" else hashlib.sha256(s).hexdigest()
        print(f"  {i}. GEELY{{{payload}}}")
        print(f"     [mask={enc}, flag=secret.hex()]" if how == "hex"
              else f"     [mask={enc}, flag=sha256(secret)]")
        print(f"     secret = {s.hex()}")


if __name__ == "__main__":
    main()
