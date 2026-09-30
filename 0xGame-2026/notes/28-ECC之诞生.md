# 28 · [深具传统的ECC之诞生]

- **flag**: `0xGame{master's touch}`
- **分类**: Crypto（动态环境，1000 分，1 解）
- **目标**: `nc1.ctfplus.cn:25121`（非交互式，连上即打印参数并断开；参数跨连接固定）
- **PoC**: `scripts/28-solve.py`（`--live` 可重新抓取参数；默认离线复现）
- **证据**: `evidence/28-banner.txt`、`evidence/28-multi-connect.txt`、`evidence/28-submit.txt`、`evidence/28-stop.txt`

## 1. 协议

连上去只输出一段固定 banner（无任何输入点，`nc ... < /dev/null` 即得）：

```
[+] Invalid Touch
[+] p = 380025560263444925282186340357451425457046895363401263284043
[+] E: y^2 = x^3 + 3*x + 0 mod p
[+] A pair of points was randomly selected.
[+] G = (89416635389252243162818482998273067753365476637225933437342, 246277781258250668709138589808946483685012465285148814183503)
[+] Q = (329460413071651533403262472631632126805896556373758724864455, 299273891016902567464505544081763716760408274149519169100436)
[+] Q = bytes_to_long(flag) * G
```

多连几次（`evidence/28-multi-connect.txt`）确认 **p / G / Q 完全固定** —— 题面说 "randomly selected"
但实际是硬编码（或固定种子），所以这是一道**纯离线密码分析题**，不是交互题。

## 2. 关键判断：不是 ECDSA，是纯 ECDLP

brief 里列的 ECDSA nonce 重用 / 无效曲线 / 签名范围校验等方向**全部排除**：
服务只给 `G` 和 `Q = d·G`，**没有任何签名 `(r,s)`、没有 `z`**，也没有可提交的交互点。
`[+] Invalid Touch` 只是装饰性提示（呼应 flag 里的 "touch"）。

所以目标是解 `d = log_G(Q) = bytes_to_long(flag)`。

## 3. 曲线结构：超奇异 + 阶完全光滑

```python
p ≡ 3 (mod 4)          # p % 4 == 3
E: y² = x³ + 3x        # j-invariant = 1728 (b = 0)
```

对 `y² = x³ + ax`，当 `p ≡ 3 (mod 4)` 时曲线**超奇异（supersingular）**，迹 `t = 0`，因此

```
#E(F_p) = p + 1
```

用自写的 EC 运算验证：`(p+1)·G = O`、`(p+1)·Q = O` ✅

然后对 `p+1` 做因式分解（sympy `factorint`，秒出）：

```
p + 1 = 2² · 116869069 · 172348369 · 261535163 · 345477907
            · 355841179 · 357636161 · 410202269
```

**全部是素数，最大只有 29 bit** → 阶完全光滑，Pohlig–Hellman 直接秒。

`ord(G) = (p+1)/2 = 190012780131722462641093170178725712728523447681700631642022`
（`G` 是 2-torsion 之外的点，少了因子 2）

## 4. 解法：Pohlig–Hellman + BSGS

因式全是 1 次幂，对每个素因子 `q` 只需一次 BSGS：把 `G` 投到 `q` 阶子群
（`G_q = (ordG/q)·G`），同样投影 `Q`，在 29-bit 群里 BSGS（表大小 ≈ √q ≈ 2×10⁴）求 `d mod q`，
最后 CRT 合成 `d mod ord(G)`。

```python
for q, e in factorize(ordG).items():
    gamma = ec_mul(ordG // q, G)
    d = 0
    for k in range(e):
        Qk = ec_mul(ordG // (q**(k+1)), ec_add(Q, ec_mul(-d, G)))
        d += bsgs(gamma, Qk, q) * (q**k)
    residues.append(d % q**e); mods.append(q**e)
d = crt(mods, residues)
```

得到

```
d = 18134719827048627907749248473909097355496002454513789
long_to_bytes(d) = b"0xGame{master's touch}"
```

注意 `bytes_to_long(flag) < ord(G)`，所以 `k = 0` 那一支就是真 flag（脚本会扫 `k = 0..63` 找 `0xGame{`）。

## 5. 本地验证

```python
ec_mul(bytes_to_long(b"0xGame{master's touch}"), G) == Q   # True
```

即 `Q = d·G` 精确成立 → 提交。

## 6. 提交与释放

```
python3 scripts/ctfplus.py submit 28 "0xGame{master's touch}"
-> {"code":200,"msg":"OK","data":{"result":true}}      ✅ 接受

python3 scripts/ctfplus.py stop 28
-> {"code":200,"msg":"OK","data":{"result":true}}      ✅ 槽位已释放
```

## 7. 一句话总结

题面「学生记录是**真实**的吗？」的落点不是伪造签名，而是：
**曲线的阶 `#E = p+1` 是光滑的**，所以 `d·G` 这层「看起来安全」的包装毫无意义 ——
这恰好就是 ECC 诞生史里最经典的一课（Pohlig–Hellman 对光滑阶群体的毁灭性打击，
以及为什么现代曲线必须选阶含大素因子、还要防超奇异/MOV）。
