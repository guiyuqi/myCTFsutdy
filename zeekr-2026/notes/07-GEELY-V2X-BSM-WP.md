# GEELY V2X BSM Writeup

**题目名称：**

**题目类型：** 车联网安全 / 密码学 / ECDSA nonce 复用

**FLAG：**

```
GEELY{V2X_898cafad25db5e3fc74a1364_c7df2614b26ca968f35eba0b}
```

---

## 解题思路

**1. 报文结构**（`signed_message_profile.txt`）：

```
GEVX | ver | cidlen | cert_id(8) | tbs_len(2,BE) | sig_len(1) | sig r||s(64) | TBS(ASCII)
```

TBS 直接做 `SHA-256(TBS)` 验 ECDSA P-256。

**2. 三帧解析**，发现 frame1 和 frame2 的 `r` **完全相同**（`372320da…959e8b`），但 TBS 不同 → 同一条随机数 k 签了两条消息：

```
k = (h1 - h2) / (s1 - s2) mod n
d = (s1·k - h1) / r       mod n
```

frame3 的 `r` 不同，是干扰项。

**3. 交叉验证**：`d·G` 正好等于 A31F、B47D 两张证书里的公钥（两者公钥字节完全相同，C92A 是另一把）——正是题面说的"同一私钥映射多张伪名证书"，也正好对应被 suspended 的那两张。

```
d = 4b04c9f2dc7b53f87b8a0752b9ec9f391edc760379baf1a41dfc4a1c062be59b
```

**4. 组 token**：

```
TOKEN = SHA-256("GEELY-V2X-KEY-RECOVERY" || d(32B) || cid1(8B) || cid2(8B) || SHA-256(DER(CA)))
FLAG  = GEELY{V2X_<token前24hex>_<token后24hex>}
```

cid 用完整 8 字节（`2561` 是 authority register，不能只取 4 字节 serial），按升序排：
`256100002561a31f`、`256100002561b47d`。

**5. 复现**：`python3 scripts/v2x_solve.py`

---

## 编写脚本

```python
#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

BASE = Path(__file__).resolve().parent.parent / "work" / "v2x" / "attachments"
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# 解析报文
frames = []
for line in (BASE/"evidence"/"v2x_session.jsonl").read_text().splitlines():
    o = json.loads(line); b = bytes.fromhex(o["raw_hex"])
    cid = b[6:14]; off = 14
    tbslen = int.from_bytes(b[off:off+2], "big"); off += 2
    sig = b[off+1:off+65]; tbs = b[off+65:off+65+tbslen]
    frames.append({"cid": cid,
                   "r": int.from_bytes(sig[:32], "big"),
                   "s": int.from_bytes(sig[32:], "big"),
                   "h": int.from_bytes(hashlib.sha256(tbs).digest(), "big")})

# 找 r 重复的两帧，反解 k 和私钥 d
f1, f2 = next((a, b) for i, a in enumerate(frames) for b in frames[i+1:] if a["r"] == b["r"])
k = (f1["h"] - f2["h"]) * pow(f1["s"] - f2["s"], -1, N) % N
d = (f1["s"] * k - f1["h"]) * pow(f1["r"], -1, N) % N
print(f"k = {k:064x}\nd = {d:064x}")

# 验证 d 能复现两条签名
priv = ec.derive_private_key(d, ec.SECP256R1())
for f in (f1, f2):
    s = pow(k, -1, N) * (f["h"] + f["r"] * d) % N
    print("sig ok:", s == f["s"])

# 组 token
ca_hash = hashlib.sha256(
    x509.load_pem_x509_certificate((BASE/"pki"/"ca_cert.pem").read_bytes())
        .public_bytes(Encoding.DER)).digest()
cids = sorted([f1["cid"], f2["cid"]])
token = hashlib.sha256(b"GEELY-V2X-KEY-RECOVERY" + d.to_bytes(32, "big")
                       + cids[0] + cids[1] + ca_hash).hexdigest()
print(f"TOKEN = {token}")
print(f"FLAG  = GEELY{{V2X_{token[:24]}_{token[-24:]}}}")
```
