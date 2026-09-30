# 赛前工作区 / 环境自检报告

- 时间: 2026-09-19（WSL2, `WIN-RB19LNJ7C6S`）
- 工作区: `~/ctf-2026`
- 沙箱: workspace-write，approval policy = ask

---

## 1. AGENTS.md 规定的三项自检 —— 通过

```bash
source ~/re-tools/fw-env.sh     # 环境已激活, exit 0
rea --version                   # 3.1.0        ✅ 期望 3.1.0
qemu-mipsel-static --version    # 7.2.0        ✅
command -v fw-decompile unsquashfs rea   # 三者齐全 ✅
```

附带确认可用：

| 组件 | 状态 |
|---|---|
| Ghidra | 12.1.3 PUBLIC，`analyzeHeadless` 可调用 ✅ |
| capstone / unicorn / lief | OK ✅ |
| angr | 9.3.4 ✅ |
| pwntools | OK ✅ |
| qemu 静态二进制 | 34 个架构 ✅ |

## 2. 题目形态 —— 与 AGENTS.md 的假设不符

`firmware/` 下**只有一个裸二进制**，没有固件镜像：

```
firmware/uhttpd
  ELF 64-bit LSB pie executable, x86-64, dynamically linked,
  interpreter /lib/ld-musl-x86_64.so.1, no section header   ← 已 strip
  sha256 26b222136da3fbf07df11fc455fd3c11f0f0bb797b03d05a24c00791302f24fc
  58090 bytes
```

后果：

- 不是 MIPS，**没有 MBR 分区表、没有 squashfs** → 标准流程的 step 2 / 3 / 5 全部不适用；
- 自检里的 `qemu-mipsel-static` 虽然通过，但对本题**没有意义**；
- 题目性质是**单个 x86-64 用户态程序的静态逆向**（OpenWrt `uhttpd`，含
  `uhttpd_lua.so` / `uhttpd_ucode.so` / `uhttpd_ubus.so` 插件字符串，
  默认配置 `/etc/httpd.conf`）。

## 3. ❌ 最严重：已有反编译产物是残缺的

`decompiled/uhttpd_.c`（1084 行）**不可用**：

| 指标 | 实际值 |
|---|---|
| Ghidra 报告 `FUNCTIONS_TOTAL` | 313 |
| `### FUNCTION_INDEX` 列出的函数 | 202 |
| **实际写出函数体** | **只有 6 个** |
| `### DECOMPILED_COUNT` 收尾行 | **缺失** → 证明运行被中途杀死 |

已写出的 6 个：`_init`, `FUN_00104003`, `entry`, `_FINI_0`, `_INIT_0`, `FUN_00104ca2`
（文件在 `FUN_00104ca2` 结尾处直接断掉）。

### 根因（已复现）

`~/re-tools/bin/fw-decompile` 最后一行：

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "${ARGS[@]}" 2>&1 | tee "$OUT" | \
  sed -n '/### DECOMPILED/,$p' | head -100
```

`head -100` 读完 100 行就退出 → **SIGPIPE 逆着管道往上杀** `sed` → `tee` →
`analyzeHeadless`。于是 `tee "$OUT"` 写进 `.c` 的内容**也是被截断的**，
而脚本照样打印「完整结果已保存」并以 exit 0 结束 —— 失败是**静默的**。

复现证据（与本题无关的最小实验）：

```bash
$ seq 1 100000 | tee /tmp/sp_test.txt | head -100 > /dev/null
$ wc -l < /tmp/sp_test.txt
8411        # 而不是 100000
```

附带：`evidence/decompile-test.log` 里 `[*] 函数数 : 15`，
说明上次跑的是 **15**，而 AGENTS.md 写的是 **40**。

**结论：做本题前必须绕过这个管道重跑反编译，否则拿到的是 3% 的伪代码。**

## 4. ❌ 二进制当前无法执行 / 仿真

- 需要 `/lib/ld-musl-x86_64.so.1` —— 系统上没有，`~/re-tools` 里也没有任何 `ld-musl*`；
- `~/re-tools/bin/` 的 qemu 只到 `qemu-i386-static`，**没有 `qemu-x86_64-static`**；
- 直接执行报错：

```
$ ./firmware/uhttpd -h
bash: ./firmware/uhttpd: cannot execute: required file not found
```

→ 标准流程 step 7「仿真」目前**做不了**。纯静态逆向不受影响。

> **更正（见 `01-environment-fix-verification.md`）**：本节说「只缺 musl loader」**不准确**。
> 实际 `readelf -d` 显示它还依赖 `libubox` / `libjson_script` / `libblobmsg_json`
> （`.so.20230523` → OpenWrt 23.05），主机同样没有。用 alpine 的 musl loader 实测，
> 即便有 loader 也因这组库缺失而无法启动。真正的阻塞是缺 OpenWrt 库，不是 loader。

## 5. ⚠️ 其他偏差

| 项 | 说明 |
|---|---|
| `rizin` / `r2` | fw-env.sh 把 `rizin -A ...` 列为常用命令，但**实际不存在**（re-tools 里没有）。仅能走 docker Kali，而 `docker pull` 按 AGENTS.md 需先问人类 |
| `binwalk` | 缺失（AGENTS.md 自检未要求；本题非镜像，不需要） |
| Ghidra 偏好目录 | 跑的是 12.1.3，却读 `~/.config/ghidra/ghidra_12.1.2_PUBLIC/preferences`（版本目录不一致，非阻塞） |

## 6. 工作区现状

- `work/` 空、`notes/` 空（本文件是第一条笔记）→ **尚未开工，无 flag 记录**；
- `scripts/DecompileScript.java`、`ghidra-proj/fwproj` 已就绪；
- `strings` 里**没有 flag 明文**（正常，需要逆向找校验逻辑）；
- `firmware/` 原文件未改动，哈希已记录于上。

---

## 建议的下一步（待人类确认）

1. **不要改 `~/re-tools/bin/fw-decompile`**（AGENTS.md：re-tools 只读、有问题先报告）。
   改为在工作区内直接用 `analyzeHeadless` 调 `scripts/DecompileScript.java`，
   **不带 `| head -100`**，把完整输出落到 `work/` 或 `decompiled/`；
   建议先跑 `maxFuncs=313`（或按需过滤）拿到完整伪代码。
2. 若要动态验证，需要拿到 x86-64 的 musl loader（或 `qemu-x86_64-static`）—— 这属于
   「装新工具」，需人类批准。
3. 主攻方向：`uhttpd` 的请求处理 / 认证 / CGI 分发路径 —— 从
   `FUN_00104003`（3065 字节，疑为 `main`）和 `/etc/httpd.conf` 解析逻辑入手。
