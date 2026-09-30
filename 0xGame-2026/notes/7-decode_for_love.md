# 7 · decode for love

- **flag**: `0xGame{ENCODINGGETTT}`
- **分类**: Crypto（离线，无容器） | 900 分 | 5 人解出
- **附件**: `firmware/7_decode_for_love/week1 Crypto decode for love.txt`
  （中文故事 + 最后一行 64 个 emoji）
- **成品脚本**: `scripts/7-solve.py`（标准库 + `cryptography`，直接 `python3 scripts/7-solve.py`）
- **证据**: `evidence/7-solve-output.txt`、`evidence/submit-log.jsonl`
- **提交**: `python3 scripts/ctfplus.py submit 7 '0xGame{ENCODINGGETTT}'` → `{"code":200,"msg":"OK","data":{"result":true}}`

---

## 结论：本题不是原帖那套摩斯/T9/栅栏

题目描述里的 2009 年贴吧「5 层加密」（原帖实际层序见文末）只是**背景故事**。
本题是改编版，实际 5 层是：

| # | 层 | 输入 | 算法 / 参数 | 输出 |
|---|---|---|---|---|
| 1 | 表情替换 | 64 个 emoji | emoji-aes（aghorler/emoji-aes）65 项表逆映射，`rotation=0` | `U2FsdGVkX1+e4YLKkWANEPJ5/phYjv+fWaS4PIVVthOHtVdT3DRT1/42pnALKngT` |
| 2 | AES | 上面的 base64 串 | CryptoJS AES-256-CBC，passphrase **`0x2026`**，`Salted__` 格式（EVP_BytesToKey/MD5） | `TFVKVktQVU5OTEFBQQ==` |
| 3 | Base64 | `TFVKVktQVU5OTEFBQQ==` | base64 解码 | `LUJVKPUNNLAAA` |
| 4 | 凯撒 | `LUJVKPUNNLAAA` | 位移 7（逐字符 `+7 mod 26` 加密；26 个位移里唯一出英文） | `ENCODINGGETTT` |
| 5 | flag 包装 | — | 头 `0xGame{...}` | `0xGame{ENCODINGGETTT}` |

（把「emoji 替换 / AES / AES 输出自带的 base64 / 内层 base64 / 凯撒」算作 5 层，正好对上题面的「5 层加密」。）

## 每一层的判定证据

### 层1：emoji → base64 = emoji-aes

emoji 表来自 [aghorler/emoji-aes](https://github.com/aghorler/emoji-aes) 的 `js/emoji-aes.js`：

```
🍎🍌🏎🚪👁👣😀🖐ℹ😂🥋✉🚹🌉👌🍍👑👉🎤🚰☂🐍💧✖☀🦓   -> a..z
🏹🎈😎🎅🐘🌿🌏🌪☃🍵🍴🚨📮🕹📂🛩⌨🔄🔬🐅🙃🐎🌊🚫❓⏩   -> A..Z
😁😆💵🤣☺😊😇😡🎃😍✅🔪🗒                              -> 0..9 + / =
```

- 附件 64 个 emoji **全部命中**该表（无缺失），且映射出的 base64 以 `U2FsdGVkX1`（
  base64 的 `Salted__`）开头 → 表选对了。
- 工具本身有个 `rotation` 参数（0..64）。**把 0..64 全部枚举**，只有 `rotation=0` 能得到
  `Salted__` 头 + 合法 PKCS7 填充的 AES 明文 → `rotation=0` 唯一解。
- 顺带记录：`emoji-aes` 的 JS 实现有一个已知怪癖 —— 它只对 `a-z`/`A-Z`/`0-9` 逐字符 replace，
  所以映射表必须是「a-z A-Z 0-9 + / =」这 65 项；本题密文正好用到其中 41 个。

### 层2：AES 密钥就是题面给的 `0x2026`

`CryptoJS.AES.encrypt(msg, passphrase)` 的默认输出 = `"Salted__"(8B) + salt(8B) + ct`，
再用 `EVP_BytesToKey(MD5)` 从 passphrase+salt 派生 32B key + 16B IV。

- passphrase = `0x2026`（题干「密码是0x2026」）→ 解出 `TFVKVktQVU5OTEFBQQ==`，PKCS7 填充合法（12×0x0c）。
- 交叉验证：`2026` / `0X2026` / 尾部带标点等变体全部解不出合法填充；
  AES-128（klen=32）、AES-192（klen=40）也不出合法填充 → 确实是 AES-256 + `0x2026`。

### 层3：内层又是 base64

`TFVKVktQVU5OTEFBQQ==` base64 解码 → `LUJVKPUNNLAAA`（13 字节，全大写字母）。
另外单独验证过：「先对 base64 串做凯撒再解码」只有位移 0 能得到可打印串 → 这一层就是普通 base64。

### 层4：凯撒位移 7

`LUJVKPUNNLAAA` 跑完 26 个位移，**只有 shift=7** 得到可读英文 `ENCODINGGETTT`
（8 个字符的英文单词 `ENCODING` 不可能是巧合）。

```
-0 LUJVKPUNNLAAA   -7 ENCODINGGETTT   -13 YHWIXCHAAYNNN
-1 KTIUJOTMMKZZZ   -8 DMBNCHMFFDSSS   -19 SBQCRWBUUSHHH
...                ...                -25 MVKWLQVOOMBBB
```

即加密方向是 `明文 + 7 mod 26`（`T+7 -> A` 循环）。

## 已排除的方向（避免后人重复劳动）

- **不是**原帖的摩斯 / 手机九宫格 T9 / 栅栏 / 键盘 QWERTY 替换：emoji 层解出后直接是
  `Salted__` + AES 结构，中间没有任何摩斯码或数字串。
- **旋转枚举**：emoji-aes `rotation` 0..64 全试过，只有 0 有效。
- **凯撒之后再套层**：把 `ENCODINGGETTT` 再喂给 栅栏(2~8 栏，zigzag 与「分栏」两种实现)、
  倒序、Atbash、栅栏+凯撒的各种组合，均无更优输出；`ENCODINGGETTT` 的字母重排也不存在
  更合理的英文（`DECODING` 需要两个 D，本例只有一个 D）→ 这一层就是终点。
- **隐藏字符**：附件无零宽字符 / 控制字符 / 行尾空白，故事文本无隐写。

## 原帖（背景）的实际 5 层

供对照，来自 [2009 年转贴存档](https://www.cnblogs.com/wordmy/archive/2009/02/11/1388558.html)：

```
****-/*----/----*/****-/...
  → 摩斯码   (****- = 41 这类数字对)
  → 手机九宫格 T9  (41 94 41 ... -> G Z G T G O G X N C S)
  → 电脑键盘 QWERTY 替换 (G=O Z=T ... -> O T O E O I O U Y V L)
  → 栅栏 (2 栏)  -> O O T U O Y E V O L I
  → 倒序        -> I L O V E Y O U T O O
```

本题只沿用了「层叠 + 最终表白」的梗，实际用的是 emoji-aes + AES + 双 base64 + 凯撒。

## 复现命令

```bash
cd ~/ctf-2026
python3 scripts/7-solve.py
# [1] 表情替换(rotation=0) : U2FsdGVkX1+e4YLKkWANEPJ5/phYjv+fWaS4PIVVthOHtVdT3DRT1/42pnALKngT
# [2] AES-256-CBC 解密   : TFVKVktQVU5OTEFBQQ==
# [3] base64 解码        : LUJVKPUNNLAAA
# [4] 凯撒位移 7       : ENCODINGGETTT
# [+] FLAG = 0xGame{ENCODINGGETTT}
```
