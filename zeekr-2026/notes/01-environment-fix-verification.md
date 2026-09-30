# 环境修复验证报告

- 验证时间: 2026-09-19 08:33–08:36
- 验证方式: 独立重跑 + 与你的产物逐函数比对 + 功能实测
- 结论速览: **反编译 bug 已修复并验证通过；执行/仿真与 rizin 仍未修复，其中执行问题的真正原因比我上次报告更严重**

---

## ✅ 1. `fw-decompile` 管道 bug —— 已修复，验证通过

### 修复内容（`~/re-tools/bin/fw-decompile`, mtime 08:26）

1. 落盘方式改为直接重定向，**不再有会提前关闭的管道**：
   `... | tee "$OUT" | sed | head -100` → `> "$OUT" 2>&1`
2. 新增**完整性护栏**：缺 `### DECOMPILED_COUNT` 就报 `[!!] 运行未正常结束` 并 `exit 1`
3. 新增统计：二进制函数总数 / 成功数 / 失败数
4. `fw-env.sh`（mtime 08:32）删掉了 `rizin` 的错误推荐，并如实标注 Kali 镜像是裸镜像

### 效果对比

| | 修复前 | 修复后 |
|---|---|---|
| `decompiled/uhttpd_.c` | 1084 行 / **6** 个函数体 | 6508 行 / **202** 个函数体 |
| `DECOMPILED_COUNT` | **缺失**（被 SIGPIPE 杀死） | `202` |
| 失败数 | — | `0` |

### 我的独立验证

用**全新 Ghidra 项目**重跑一次，两份产物互相对照：

```
我的: size=222861 lines=6506 bodies=202  DECOMPILED_COUNT: 202
你的: size=223023 lines=6508 bodies=202  DECOMPILED_COUNT: 202
→ 202 个函数签名逐一完全一致 ✅
```

（行数差 2 行、字节差 162 是日志前缀里的项目路径不同，函数体本身完全一致。）

### 护栏本身也验证有效

我故意跑失败的两次，它都正确报错而不是假成功：

```
[!!] 运行未正常结束（缺少 DECOMPILED_COUNT 收尾行），产物可能不完整
     exit=1
```

这正是修复前缺失的行为 —— 以前无论截断与否都打印「完整结果已保存」并 exit 0。

---

## ❌ 2. 执行 / 仿真仍不可用 —— 且比我上次说的更严重

**先更正我自己上次报告的一个不准确说法**：我当时说「只缺 musl loader」。实际
`readelf -d` 显示它依赖一整组 OpenWrt 库：

| NEEDED 库 | 主机 |
|---|---|
| `libubox.so.20230523` | ❌ 无 |
| `libjson_script.so.20230523` | ❌ 无 |
| `libblobmsg_json.so.20230523` | ❌ 无 |
| `libjson-c.so.5` | ✅ 有 |
| `libgcc_s.so.1` | ✅ 有 |
| `libc.so` (musl) | ❌ 无 loader |

我用**本地 alpine 镜像**（自带 `/lib/ld-musl-x86_64.so.1`）绕过缺失的 loader 做了功能实测：

```bash
docker run --rm -v ~/ctf-2026/firmware:/fw --entrypoint /fw/uhttpd \
  docker.1panel.live/library/alpine:3.20 -h
```

```
Error loading shared library libubox.so.20230523: No such file or directory (needed by /fw/uhttpd)
Error loading shared library libjson_script.so.20230523: ...
Error loading shared library libblobmsg_json.so.20230523: ...
Error loading shared library libjson-c.so.5: ...
Error loading shared library libgcc_s.so.1: ...
Error relocating /fw/uhttpd: uloop_done: symbol not found
Error relocating /fw/uhttpd: json_script_init: symbol not found
...
```

**结论：真正的阻塞不是 musl loader，而是缺 OpenWrt 的 `libubox` / `json_script` /
`blobmsg_json` 这一套。** `20230523` 对应 OpenWrt 23.05。要动态跑，需要的是
**OpenWrt 23.05 x86_64 的 rootfs（或那几个 .so 的 musl 版）**，而不是单独一个 loader。

另：`qemu-x86_64-static` 仍不存在（re-tools 只到 `qemu-i386-static`）；
主机仍无 `/lib/ld-musl-x86_64.so.1`。

---

## ❌ 3. rizin / r2 仍缺失

`rizin`、`r2`、`radare2` 在 PATH 与 `~/re-tools/bin` 里都不存在。
但 `fw-env.sh` 已不再宣称有 —— 文档层面已修正，工具层面未补。
附带确认：`fwctf/analysis:1` 镜像里 **也没有** r2 / binwalk / sasquatch / unsquashfs / musl。

---

## ⚠️ 4. 新发现：agent 在沙箱内无法直接调用 `fw-decompile`（两个独立原因）

### (a) Ghidra 要往工作区外写配置

```
java.io.FileNotFoundException: ~/.config/ghidra/ghidra_12.1.2_PUBLIC/java_home.save
  (Read-only file system)
ERROR: Unable to prompt user for JDK path, no TTY detected.
```

在 workspace-write 沙箱下 `~/.config` 只读 → Ghidra 启动器直接失败。
**实测设 `JAVA_HOME` 无效**，仍然失败。本次验证是在提升到 `danger-full-access` 后才跑通的。
（顺带：仍存在版本目录不一致 —— 跑 12.1.3 却读写 12.1.2 的 config。）

### (b) 项目里已有同名程序，重复运行必然失败

```
ERROR REPORT: Found conflicting program file in project: /uhttpd (HeadlessAnalyzer)
ERROR REPORT: Import failed for file: .../firmware/uhttpd
```

`ghidra-proj/fwproj` 里已经导入了 `/uhttpd`，`-import` 不会覆盖 → 导入失败 →
`-postScript` 不执行 → 没有 `DECOMPILED_COUNT` → 护栏 exit 1。
我验证时用 `FW_PROJ=<新目录>` 绕开。

> 影响：比赛期间我**无法自主重跑反编译**，除非给新 `FW_PROJ` 且放行 `~/.config` 写入。

---

## 建议

1. **反编译已可放心使用**：`decompiled/uhttpd_.c` 202/202 完整，静态分析可以推进。
2. 若要我能自主重跑：每次指向新的 `FW_PROJ` 目录；或允许 `danger-full-access`；
   或让 Ghidra config 落到工作区内（改 re-tools，需你确认）。
3. 若要动态仿真：准备 **OpenWrt 23.05 x86_64 rootfs**（含 musl 版
   libubox / json_script / blobmsg_json / json-c）。属「装新工具」，需你批准。

## 本轮产生的文件

- `evidence/decompile-fix-verify.log` —— 我的独立重跑日志（202/202, exit=0）
- `evidence/verify-decompiled/uhttpd_.c` —— 我的独立验证产物（与你的逐函数一致）
- 原始二进制未改动，sha256 仍为 `26b222136da3fbf07df11fc455fd3c11f0f0bb797b03d05a24c00791302f24fc`
