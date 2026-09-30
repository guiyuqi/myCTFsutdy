# 36 · ez_upx —— 结论笔记

- **flag**: `0xGame{N0www_y0u_kn0w_UPX!!!}`
- **提交**: `python3 scripts/ctfplus.py submit 36 '0xGame{N0www_y0u_kn0w_UPX!!!}'`
  → `{"code": 200, "msg": "OK", "data": {"result": true}}`（2026-09-28 10:47，一次成功）
- **分值 / 类型**: 701 / Reverse，离线题（无容器）
- **附件**: `firmware/36_ez_upx/attachment1.zip` → `attachment1.exe`

## 一、识别

```
$ file attachment1.exe
PE32+ executable for MS Windows 5.02 (console), x86-64, 3 sections
```

节名为 `UPX0 / UPX1 / UPX2`，`0x205` 处有 `UPX!` 魔数：

| 节 | VA | VSize | RawPtr | RawSize | 说明 |
|---|---|---|---|---|---|
| UPX0 | 0x1000 | 0xb000 | 0x200 | 0 | 解压目标区（原始代码/数据） |
| UPX1 | 0xc000 | 0x3000 | 0x200 | 0x2600 | UPX stub + LZMA 压缩数据 |
| UPX2 | 0xf000 | 0x1000 | 0x2800 | 0x200 | stub 自己的导入表 |

- EP = `0x40d960`（VA），落在 UPX1 内。
- 导入只有 5 个：`KERNEL32!LoadLibraryA/ExitProcess/GetProcAddress/VirtualProtect`、`msvcrt!exit`
  —— 典型的 UPX stub 导入，原程序导入表是被壳运行时重建的。
- 壳头解析：`UPX!` @0x205，version=0x0d、format=0x24(36, win64 PEP)、**method=0x0e(14)=LZMA**、level=10。
  stub 起始 `lea rsi,[rip-0x1946]` → 压缩流指针，`u_len=0xb5a7`、`c_len=0x1937`。
  反汇编确认解码器就是 LZMA range coder（`bound=(range>>11)*prob`，
  概率更新 `p -= p>>5` / `p += (0x800-p)>>5`）。

**注意**：本机环境**没有 `upx` 可执行文件**（`command -v upx` 为空，全盘也没找到），
所以走的是「自己把壳跑起来」的静态/仿真脱壳路线，没有安装任何新工具。

## 二、脱壳（Unicorn 仿真 stub）

脚本：`scripts/36-solve.py`（自包含，含完整脱壳 + 求解；探索版在 `work/36_ez_upx/emulate_stub.py`）

1. 按 PE 头把 3 个节写进 Unicorn 镜像基址 `0x400000`，给 1MB 栈。
2. 把 stub 导入表里的 5 个函数重定向到假地址并 hook：
   - `LoadLibraryA` → 假句柄 `0x12340000`
   - `GetProcAddress` → 每个名字一个稳定假地址（用来重建原程序 IAT）
   - `VirtualProtect` → 返回 1
   - `ExitProcess` / `exit` → 停机
3. 从 EP 跑，当 `RIP` 第一次落回 `[0x401000, 0x40c000)`（已解压区）即 OEP，停下 dump 64KB 镜像。

实测结果（1 秒跑完）：

```
[+] stub stopped: oep, insns=2291008, oep_rip=0x401cc0
```

即 **OEP = 0x401cc0**，解压目标起始于 VA `0x401000`（`lea rdi,[rsi-0xb025]` = 0x401000），
长度 `0xb5a7`，落到 `work/36_ez_upx/unpacked_image.bin`。

仿真期间 stub 通过 `GetProcAddress` 暴露的原程序导入（直接证明了脱壳完整）：

```
msvcrt.dll: __getmainargs __initenv __iob_func _initterm _acmdln printf puts fgets
            getchar strcmp strncmp strlen strcspn memcpy malloc calloc free exit ...
KERNEL32:   UnhandledExceptionFilter VirtualProtect VirtualQuery ...
```

## 三、校验逻辑

脱壳后 `strings` 直接给出关键材料：

```
vivo50
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg=
Input flag:
Correct! Welcome to reverse engineering.
Wrong flag. Try again!
```

反汇编定位（镜像 VA）：

- `0x401576` 循环异或函数：`buf[i] ^= key[i % keylen]`
  （`div qword [rbp-0x10]` 取模 → `lea rax,[rip+0x3a68]` = `0x405000` = `"vivo50"`）。
- `0x4018ab` 引用常量 `0x405080` = `RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg=`，位于 base64 编码器内。

因此流程为：

```
flag  --xor("vivo50", 循环)-->  --base64 encode-->  == "RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg="
```

反推：

```python
import base64
raw = base64.b64decode("RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg=")
key = b"vivo50"
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(raw)).decode())
# 0xGame{N0www_y0u_kn0w_UPX!!!}
```

`len(raw)=29`，正好 29 个字符的 flag，key 长度 6 循环，输出全可打印 —— 校验自洽。

## 四、复现

```bash
cd ~/ctf-2026
source ~/re-tools/fw-env.sh
python3 scripts/36-solve.py            # 自动解压附件 + Unicorn 脱壳 + 自动求解，约 1s
python3 scripts/36-solve.py --no-emu   # 复用 work/36_ez_upx/unpacked_image.bin
```

输出（见 `evidence/36-solve.log`）：

```
b64 常量 : RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg=
xor key  : vivo50
FLAG     : 0xGame{N0www_y0u_kn0w_UPX!!!}
```

## 五、踩坑 / 备注

- 环境无 `upx`，`upx -d` 路线不可用；Unicorn 跑 stub 是等价且更通用的替代
  （被魔改 UPX 头也能过，因为完全不看壳头，直接执行壳）。
- 首次仿真 dump 时误判输出起点为 `0x400000`（实际 `lea rdi,[rsi-0xb025]` = **0x401000**），
  导致重建的 PE 为空；以「RIP 进入 0x401000~0x40c000」为 OEP 条件即可绕开该细节。
- 文件本身**没有**被魔改：节名、`UPX!` 魔数、导入表都完好，直接是 UPX 5.02 + LZMA。
- `firmware/36_ez_upx/` 原附件未改动；解压产物在 `work/36_ez_upx/`。
