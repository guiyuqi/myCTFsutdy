# 39 · z3_solver

- **分类**: Reverse（离线，无容器）
- **分值**: 773 | 11 人解出
- **flag**: `0xGame{z3_Se3ms_ezzz2z}`
- **提交**: `code: 200 / msg: OK / data.result: true` ✅

## 附件

`firmware/39_z3_solver/attachment4.zip` → `attachment3.exe`
PE32+ (x86-64, mingw-w64 console, 15872 B, stripped-but-symbol-rich `.idata`)

`strings` 关键串：
```
=== Constraint Gate ===
Every character matters. Can you satisfy them all?
flag >
Wrong length.
Correct! Constraints solved.
Nope. At least one constraint is unhappy.
```

## 思路

`fw-decompile ./attachment3.exe 40`（在 `work/39_z3/` 下跑）→ 主逻辑三件套：

- `FUN_004016c2` — `main`：读一行 → `strcspn("\r\n")` → **`strlen(input) == 0x17`（23 字节）** → 调 gate。
- `FUN_00401550` — 唯一的 gate，线性方程组，**没有分支迷宫、没有表驱动、没有非线性**。

反编译原文（可读性已整理）：

```c
for (i = 0; i <= 0x16; i++) {                     // 23 轮
    if (input[i] < 0x20 || input[i] > 0x7e) return 0;      // 必须可打印
    b1 = input[(i + 1) % 0x17];
    b2 = input[(i + 7) % 0x17];
    if ((ushort)( input[(i+4)%0x17] * 7
                + b2 * 9 + b2 * 2
                + input[i] * 3
                + b1 * 4 + b1 ) != *(short *)(DAT_00404000 + i * 2))
        return 0;
}
return 1;
```

化简后（`b2*9 + b2*2 = b2*11`，`b1*4 + b1 = b1*5`）：

```
∀ i ∈ [0,22]:  3·x[i] + 5·x[(i+1) mod 23] + 11·x[(i+7) mod 23] + 7·x[(i+4) mod 23] = C[i]
```

- 环状（模 23）线性方程，23 个未知数 × 23 条方程。
- 系数全正，最大和 `126·(3+5+11+7) = 3276`，**16 位无溢出**，所以直接当整数等式即可，不需要 `BitVec` 的模语义（用 `ZeroExt(16, BitVec8)` 表达最忠实）。
- `DAT_00404000` 在 `.rdata`（RVA `0x4000`，image base `0x400000`），23 个 **little-endian int16**：

```
2849 1983 2604 2603 2300 2144 2759 2593 2030 2574 2901 2565 2747
2306 3016 3019 1791 3150 2632 2019 2799 2599 2647
```

脚本**不硬编码**常量表：按 PE 节表定位 RVA `0x4000` 现场读取 —— 换附件也照样跑。

## 求解

`scripts/39-solve.py`（z3，`BitVec8` + `ZeroExt(16)`）：

```
sat
'0xGame{z3_Se3ms_ezzz2z}'      # 23 字符，长度与 0x17 吻合
[ok] 23/23 constraints verified against the binary
```

自检：把解回代到 23 条原始方程逐条比对，全部相等（脚本内 `assert`）。

## 关键命令

```bash
source ~/re-tools/fw-env.sh
cd ~/ctf-2026/work/39_z3
unzip -o ../../../firmware/39_z3_solver/attachment4.zip      # -> attachment3.exe
fw-decompile ./attachment3.exe 40                            # -> decompiled/attachment3.exe_.c
# FUN_004016c2 = main（长度检查），FUN_00401550 = gate（方程组）
python3 scripts/39-solve.py                                  # 成品脚本
```

## 坑

- **`(i+1)`/`(i+4)`/`(i+7)` 都是模 23 的环形索引** —— 23 是质数，`gcd(1,23)=gcd(4,23)=gcd(7,23)=1`，四个偏移都遍历全环，
  所以方程组是满秩的、唯一解；不要误当成线性数组边界而截断。
- 长度是 **23 而不是 `0x17`→十进制 23 的巧合**：`strlen == 0x17`，和循环上界 `0x16` 一致。
- 类型：可打印判定用 `0x20..0x7e`（不是 `isalnum`），必须显式加进 z3 约束，否则解可能落到括号外的字节。
