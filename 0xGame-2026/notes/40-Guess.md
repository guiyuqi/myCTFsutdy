# 40 · Guess

- **分类**: Reverse（无动态环境，离线题）
- **分值**: 812 | **解出人数**: 9
- **附件**: `firmware/40_Guess/attachment5.zip` → `attachment.exe` (8093040 B, sha256 见 evidence)
- **flag**: `0xGame{Congratulations_0n_y0ur_v1ct0ry：）}`
- **状态**: ✅ 已提交，平台返回 `{"code":200,"msg":"OK","data":{"result":true}}`

---

## 1. 结论先行

`attachment.exe` 是 **PyInstaller onefile** 打包的 Windows x64 控制台程序
（Python 3.14，`python314.dll`）。README 已经说明「猜数字只是幌子，
真正的 flag 没有直接输出」，实际逻辑：

```
guess == target  →  print("flag is 0xGame{I'm just kidding :D}")   # 假 flag
                    secret = tea_decrypt(FLAG_CIPHERTEXT, TEA_KEY)
                    if not secret.startswith(b'0xGame{'): raise RuntimeError
                    # 注意：secret 只做完整性检查，从不打印！
```

真 flag 就是 `tea_decrypt` 的解密结果。**猜数字完全无关**，玩游戏是浪费时间
（而且猜中也只得到一个假 flag）。

## 2. 关键常量（从 marshal 出来的 `game` 模块）

| 名称 | 值 |
|---|---|
| `DELTA` | `2654435769` = `0x9E3779B9` |
| `MASK` | `0xFFFFFFFF` |
| `TEA_KEY` | `b'guess_secret_key'`（正好 16 字节 → `<4I` 四个 round key） |
| `FLAG_CIPHERTEXT` | `1102c93630fe71bd39ad4e4cc34600299897001c3300581e465c56d2a11ba430819e7a59f1c20188f40ccba3a312dd3d`（48 B = 6 个 XTEA block） |

## 3. 解题过程

### 3.1 类型识别

```bash
file attachment.exe
# PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections

strings -n 10 attachment.exe | grep -iE 'pyinstaller|_MEIPASS|python3'
# Could not load PyInstaller's embedded PKG archive ...
# python314.dll / pyi-contents-directory / _pyinstaller_pyz
```

立刻判定 **PyInstaller + Python 3.14**，不去碰 PE 反汇编。

### 3.2 手工解析 CArchive（没装 pyinstxtractor，也不许 pip install）

CArchive 布局：`[overlay][cookie(88B)][TOC][\n][PKG data]`，
cookie 魔数 `MEI\014\013\012\013\016`（用 `rfind` 从尾部找），
所有整数 **big-endian**：

```
cookie = magic(8) | pkglen(4) | toc_off(4) | toc_len(4) | pyvers(4) | pylibname(64)
arch_start = cookie_end - pkglen
TOC entry (18B 头 + name):
    elen(4) | epos(4) | cmprs_size(4) | uncmprs_size(4) | cmprs_flag(1) | typecode(1) | name(elen-18)
    name/offset 相对 arch_start；cmprs_flag=1 → zlib
```

本附件实测：`cookie@0x7b7d18, pkglen=7719792, toclen=3680, pyvers=314, pylib=python314.dll`，
TOC 67 条。只有 3 条是我们关心的：

```
('pyiboot01_bootstrap', 's', ...)   # 引导脚本
('game',                's', 23409, 2103, 3556, 1)   # ← 题目逻辑，zlib 压缩
('PYZ.pyz',             'z', ...)   # 标准库 PYZ
```

### 3.3 `game` 是裸 marshal 流，不是 pyc

`game` 解压后 3556 字节，首字节 `0x63` = `TYPE_CODE`，**没有 pyc 16 字节头**。
本机 Python 恰好是 3.14.4，所以直接：

```python
import marshal, dis
code = marshal.loads(open('game','rb').read())
dis.dis(code)
```

即可拿到全部反汇编。不需要 uncompyle6/decompyle3（它们也不支持 3.14）。

### 3.4 反汇编 → 认出 XTEA

`tea_decrypt(data, key)` 的反汇编是教科书级 **XTEA**（不是原版 TEA，移位是 4/5）：

```python
words = struct.unpack('<4I', key)
for offset in range(0, len(data), 8):
    left, right = struct.unpack('<2I', data[offset:offset+8])
    total = (DELTA * 32) & MASK          # 0xC6EF3720
    for _ in range(32):
        right = (right - ((((left  << 4) + words[2]) ^ (left  + total) ^ ((left  >> 5) + words[3]))) & MASK
        total = (total - DELTA) & MASK
        left  = (left  - ((((right << 4) + words[0]) ^ (right + total) ^ ((right >> 5) + words[1]))) & MASK
    result.extend(struct.pack('<2I', left, right))
# 末尾 PKCS#7 去填充：padding = result[-1]，必须 1<=padding<=8 且末 padding 字节全等于 padding
```

Python 复刻一遍解密：

```
plaintext = b'0xGame{Congratulations_0n_y0ur_v1ct0ry\xef\xbc\x9a\xef\xbc\x89}'
```

末尾两个字符是 **全角** 标点：
- `\xef\xbc\x9a` = U+FF1A `：`（全角冒号）
- `\xef\xbc\x89` = U+FF09 `）`（全角右括号）

程序自带的完整性检查 `secret.startswith(b'0xGame{')` 在本地通过 →
说明解密正确（这是题目给的免费校验点，提交前必跑）。

### 3.5 提交

```bash
python3 scripts/ctfplus.py submit 40 '0xGame{Congratulations_0n_y0ur_v1ct0ry：）}'
# {"code":200,"msg":"OK","data":{"result":true}}
```

## 4. 复现

```bash
cd ~/ctf-2026
python3 scripts/40-solve.py
# [*] 从 firmware/40_Guess/attachment5.zip 读取 attachment.exe (8093040 bytes)
# [+] flag: 0xGame{Congratulations_0n_y0ur_v1ct0ry：）}
```

脚本从**原始附件**全自动跑通：解 zip → 解析 CArchive → marshal 取常量 →
XTEA 解密 → 校验 `0xGame{` 前缀。不依赖任何新装工具，
只用标准库 `zipfile/zlib/struct/marshal`。

> 时间戳 / 中间产物：`work/40_guess/`（解包结果 `extracted/`、`README.md`）
> 证据：`evidence/40-guess.txt`

## 5. 踩坑 / 排除的方向

- **不要真的去玩猜数字**：`random.randint(0,100)` 五次机会，猜中只打印假 flag；
  且程序从不打印 `secret`，猜中与否对拿 flag 没有任何帮助。
- **不要写 angr**：`FLAG_CIPHERTEXT` 是硬编码常量 + 对称解密，
  纯静态一步到位；符号执行是多余开销。
- **注意 Python 版本**：PyInstaller 用的是 3.14（`pyvers=314`），
  `marshal` 格式和 3.12 不兼容。本机 `python3 -V` = 3.14.4，正好直接加载；
  若本机版本不符需换 3.14 解释器或手写 marshal 解析。
- **`game` 无 pyc 头**：直接 `marshal.loads` 原始字节即可，
  不要按 pyc 去跳 16 字节头。
