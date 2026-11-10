# vmshare (brz2pZwJzt8gV8r6) — Crypto / 强网杯 2026 线上赛

**状态: 已解出（唯一密钥，但题面 flag 串存在 256 个等价前像 —— 见 §5）**

## 1. 附件
`vmshare_6d3416fb746f85cad8020e41571f8b7b.zip` (3246 B) → 两个文件：
- `cipher.bin` 32 B 密文
- `encryptor` 7904 B stripped x86-64 PIE ELF

题面没有文字，只有附件链接（`content` 字段里就是 `<a href=oss…>附件下载</a>`）。

## 2. flag 格式（二进制里写死）
```
error: flag must match flag{XXXXXXX_YYYYYYY}
       where each XXXXXXX/YYYYYYY is 7 uppercase hex digits
usage: %s flag{XXXXXXX_YYYYYYY} [out.bin]
```
校验：`strlen==0x15`、前 5 字节 `flag{`、`[0xc]=='_'`、`[0x14]=='}'`、
第 5..11 / 13..19 字节 ∈ `[0-9A-Fa-f]`（`&0xdf` 后落在 0x41..0x46 或 0x30..0x39，
**大小写都收**）。

## 3. 算法（全部在 main 内联，`.text` 只有 0x65d 字节）
```
X = strtoul(flag[5:12],16)   ; Y = strtoul(flag[13:20],16)
K1 = gen(X, 0x31415926)      ; 8×uint16 = 16 B     @0x1c60
K2 = gen(Y, 0x27182818)      ; 8×uint16 = 16 B
S  = "SIMD_TINY_BLOCK_IS_A_NIGHTMARE!!"  (32 B @0xa80, 16 lanes LE)
S  = F(S, K1) ; S = F(S, K2)              @0x1cc0
out = S                                    → cipher.bin (32 B)
```
`F` 是 **16 条完全独立 16-bit lane** 的 AVX2 函数（`vpsrlw/vpsllw/vpaddw/vpxor/vpor`，
无跨 lane 混合）；每 lane 加常量 `CONST[lane]`（32 B @0xa60：
`1357 2468 369C 48AD 5BE1 6CF2 7D03 8E14 9F25 A036 B147 C258 D369 E47A F58B 069C`）。
单 lane 一轮（i=0..7）:
```
s ^= s>>5 ; t = rotl16(s,3) ; s = (K[i] + CONST[lane] + t) & 0xffff
s ^= s>>7 ; s = rotl16(s,9)
```
**注意**：`s^=s>>5` 在轮首而不是轮尾——写成轮尾会 16/16 lane 全错（踩过）。
`F` 对 s 是双射（16 步线性三角异或 + 加法 + 旋转都可逆），所以可以 MITM。

`gen(seed,C)`：`eax=((seed&0xffffff)^C)`，先 `x^=x>>13; x*=0x45d9f3b; x^=x>>16`，
再 8 轮 `x += 0x9e3779b9 + 0x7f4a7c15*i`，`x^=x>>13; x*=0x85ebca6b`，
输出 `((x^(x>>16))^(x>>32>>16)) & 0xffff`。循环 8 次 = `8*0x7f4a7c15 = 0xFA53E0A8`（cmp 常量）。

## 4. 攻击：MITM（2^24 + 2^24，16.6 s）
`seed & 0xffffff` ⇒ **只有低 24 bit 参与运算**（早期实测证实：`1000000`/`F000000`
首位数/最高半字节对密文完全无影响）。密钥空间 24+24 = 48 bit。
- 正向表：X∈[0,2^24) → `M=F(INIT,K1(X))`，取 lane0|lane1|(lane2&0xff) = 40 bit，
  与 X 打包进 uint64 排序（134 MB）。
- 反向：Y∈[0,2^24) → `M'=F^-1(cipher,K2(Y))`，二分查 40-bit 前缀，
  ~256 候选 → 用 `F` 全 256 bit 复验。
结果：**X=0x174812, Y=0x1AF718**。

## 5. ★ 歧义：cipher.bin 有 256 个等价 flag 串
24-bit 截断丢掉每半段最高十六进制位 ⇒ `X = h1·2^24 + 0x174812`、`Y = h2·2^24 + 0x1AF718`，
`h1,h2 ∈ 0..F` 共 **256 个 flag 全部字节级复现 cipher.bin**（`evidence/…/candidates.txt`，
已用原 `encryptor` 逐一验证）。另因大小写不敏感，每个还有大小写变体。

**首选 `flag{0174812_01AF718}`**（两个半段首位均为 0）：
`and eax,0xffffff` 说明作者把种子当 24-bit 用，那 `%07X` 补零 ⇒ 首位数 0。
提交优先级（31 个，先 h1=0 全 h2，再 h2=0 其余 h1）见下。

## 6. 复现
```bash
cd work/brz2pZwJzt8gV8r6_vmshare/ext
cp ../../../scripts/brz2pZwJzt8gV8r6-solve.c solve.c && gcc -O3 -mavx2 -o solve solve.c && ./solve
# 复验：
./encryptor 'flag{0174812_01AF718}' /tmp/a.bin && cmp cipher.bin /tmp/a.bin && echo OK
```
`solve.c` 通过 `mmap` 把 `encryptor` 的 `.text`/`.rodata` 按原 VMA 摆好后**直接调用二进制自己的
`gen`/`F`**（`scripts/brz2pZwJzt8gV8r6-harness.c` 是最小确认版），避免转写误差；
自写标量 `fwd` 与二进制 `F` 16/16 lane 一致后才用于反向。

## 7. 对照（三重）
- 正向：`flag{0174812_01AF718}` → 原 `encryptor` → 与 `cipher.bin` **cmp 一致**。
- 负向：`flag{0174812_01AF719}` 等 256 个之外的串 → 密文不同；lane 独立性用 `k=0,in=0` /
  `in[0]=1` / `k[0]=1` 三点探针证实。
- 平台已答出数：red/blue `solved_number` 均为 0（本题未有人解出），与"歧义导致无法唯一"
  的假设不矛盾，但**不能**据此断言作者 flag 首位非 0。
