# re-LastIgnition

- 结果：💀 未解出
- 关联 run：run-51063, run-1314496, run-1995778｜合计 token ≈ 45.5M

## 题面 / 结论 / 可复用资产
**题面**：

```
re-LastIgnition
```

**run-51063 最后事实**：

- 运行期 12.3k 个 ladder 相关 32B 值当 H1/cred 全负；gateway 另含 20 条 05A0/05A1 SYNC 帧（各带 8B 高熵块+3B 尾）；宿主可直连 github.com（HTTP 200） 本 Step 收尾（未取得 flag），三条实测增量： 1) 用离线判定（H1=sha256(b"LI7/view\0"+cred)，hmac_sha256(H1, b"LI7/tag\0"+B[:0x24]+B[0x44:])==B[0x24:0x44]，MSG 233KB，约 0.1ms/候选）对 shared/live2/hits.log 里 **全部 12339 条 SHA-256 调用记录**（保留 200 字节内输入 hex）逐条取 **[0:32] 前缀 / 末 32 字节 / sha256(整条输入)** 共 7423 个不同 32 字节值，分别当 **H1 直接用**（此前只当 cr
- problem.zip 无隐藏元数据（6 文件、comment/extra 全空、时间戳统一 2026-01-01）；离线 HMAC oracle 实测 0.115ms/候选（msg 233335B，8 核≈69k/s）；mem.bin 20.5M 窗口扫描已在 tmux shared:scanmem25 重启但本轮无结果 本 Step 仅两条低成本实测（未取得 flag）： 1) 附件包元数据核查（有界负结论）：python3 zipfile 读取 problem.zip，entries 恰 6 个（last_ignition.exe 1142784、gateway.canlog 273920、body.canlog 270080、powertrain.canlog 270208、recovery.bundle 233359、README.md 839）；每个 entry 的 comment 与 extra 均为空、ZIP 全
- problem.zip 无隐藏元数据（6 文件、comment/extra 全空、时间戳统一 2026-01-01）；离线 HMAC oracle 实测 0.115ms/候选（msg 233335B，8 核≈69k/s）；mem.bin 20.5M 窗口扫描已在 tmux shared:scanmem25 重启但本轮无结果 本 Step 仅两条低成本实测（未取得 flag）： 1) 附件包元数据核查（有界负结论）：python3 zipfile 读取 problem.zip，entries 恰 6 个（last_ignition.exe 1142784、gateway.canlog 273920、body.canlog 270080、powertrain.canlog 270208、recovery.bundle 233359、README.md 839）；每个 entry 的 comment 与 extra 均为空、ZIP 全

**题面**：

```
Last Ignition：三个 ECU 留下了断电前的 CAN-FD 离线诊断记录与恢复包。恢复本次维护的 32 字节凭据。exe 用法：last_ignition.exe gateway.canlog body.canlog powertrain.canlog recovery.bundle <64位十六进制凭据>；全零 → FAIL，正确 → OK。平台 flag 格式 flag{64位小写hex}（credential 本身）。
```

**run-1314496 最后事实**：

- 运行期三份 LI6ECU 缓冲(12858/12858/12859B)与合并后 LI7HIST1(3721B)、LI6BND(40B) 已实测 dump；它们与 coop 同样不含连续 32B cred/H1 本轮（新，全部为本人亲跑的 winedbg --gdb 断点实测，4s/次，无需 patch gate）： 1) 断点方案（比之前更省）：只断 0x1400df25d（call sub_140029600 前）即可在同一时刻拿到全部中间产物；脚本在 workspace/live7/{hook.py,hook2.py,hook3.py,cmds*.gdb,gdbwrap*.sh}，运行方式同 live4： cd live4; export HOME=$PWD/../homes WINEPREFIX=$PWD/../.wineprefix XDG_RUNTIME_DIR=/run/user/1000 WINEDEBUG=-al
- VM 主程序(779条,入口 goto 406)已完整反汇编：coop 是以 h(=SHA256("LI7/view\0"+cred)) 的 8 个 u32 为密钥的 ARX 加密容器，故 cred 不可能由 h 反推；exe 内另有未逆过的 LI9/MASK|KDF|PAGEBIT|stream 掩码分支（函数 0x1400310f0 / 0x14002f500） 本轮（bootstrap）亲跑增量，未拿到 flag： 1) VM 字节码完整反汇编（新，前几轮只有 ISA）：每条 16B={u8 op,u8 D,u8 A,u8 B,4B 填充,s64 imm}（注意不是 12B）。程序 779 条，指令0= `goto 406`，即 1–405 是子程序、406 起才是主体。已产出完整可读清单 shared/vm_dis.txt + 反汇编器 shared/dis_vm.py。关键子程序：1–12=从 coop 基址+r6 按
- VM 主程序(779条,入口 goto 406)已完整反汇编：coop 是以 h(=SHA256("LI7/view\0"+cred)) 的 8 个 u32 为密钥的 ARX 加密容器，故 cred 不可能由 h 反推；exe 内另有未逆过的 LI9/MASK|KDF|PAGEBIT|stream 掩码分支（函数 0x1400310f0 / 0x14002f500） 本轮（bootstrap）亲跑增量，未拿到 flag： 1) VM 字节码完整反汇编（新，前几轮只有 ISA）：每条 16B={u8 op,u8 D,u8 A,u8 B,4B 填充,s64 imm}（注意不是 12B）。程序 779 条，指令0= `goto 406`，即 1–405 是子程序、406 起才是主体。已产出完整可读清单 shared/vm_dis.txt + 反汇编器 shared/dis_vm.py。关键子程序：1–12=从 coop 基址+r6 按

**题面**：

```
Last Ignition（续）：找回本次维护的 32 字节凭据（flag 就是这 64 位 hex）。exe 是 oracle：全零 FAIL，正确 OK。
```

**run-1995778 最后事实**：

- bundle 前 0xc00 字节是明文结构区(含 0x1000 步长偏移表)，之后才高熵；三份 log 的 16B/帧载荷流在同一 keystream 下无任何对齐(gateway 独有的 20 帧 = A0/A1 双联记录) 本 Step 无 flag，给出三条可直接复用的实测增量（均可用指定脚本复现）： 1) 修正 fact_001/fact_002 的「bundle 0x44 起整体高熵」：逐 1024B 块算 Shannon 熵+零字节占比，bundle[0x000..0xc00] 是**明文结构区**（H≈3.96，零占比 0.55，能从 0x44 一直读到 0xc00 的整齐 16 字节记录），bundle[0xc00..233359] 才高熵（H≈7.8，零占比 0.02）。即真正被加密/掩码的只有尾部 230287 字节，头部 3072 字节（含 LI7JOIN 0x44 + LI8COOP1 头）是完全可静态
- 日志解析与凭据校验无数据依赖（sub_140005080 第5参为输出槽，非 cred）；bundle 仅含 LI7JOIN/LI8COOP1 两个 ASCII 标签且 0x390..0xa00 是 6-op 分派索引表；powertrain 比另两份多 1 帧（counter=2110000） 本 Step 只做静态判读+原始文件核对，无 flag。三条实测增量（均可复现）： 1) 「三份 log 参与 cred 判定」这一假设被否证（有界负结论）。`grep -n 140005080 main.asm` 全文件只有一处调用点 0x1400defb0；该处实参：rcx=[r14]（该 ECU 的 log 文本首址）、rdx=[r14+8]-rcx（长度）、r8d=ebx（ECU 序号 0/1/2，r14 每轮 +0x18）、r9=[rsp+0x230]（输出槽，循环前被写 0）、第 5 参数=[rsp+0x50]。进入 sub
- 日志解析与凭据校验无数据依赖（sub_140005080 第5参为输出槽，非 cred）；bundle 仅含 LI7JOIN/LI8COOP1 两个 ASCII 标签且 0x390..0xa00 是 6-op 分派索引表；powertrain 比另两份多 1 帧（counter=2110000） 本 Step 只做静态判读+原始文件核对，无 flag。三条实测增量（均可复现）： 1) 「三份 log 参与 cred 判定」这一假设被否证（有界负结论）。`grep -n 140005080 main.asm` 全文件只有一处调用点 0x1400defb0；该处实参：rcx=[r14]（该 ECU 的 log 文本首址）、rdx=[r14+8]-rcx（长度）、r8d=ebx（ECU 序号 0/1/2，r14 每轮 +0x18）、r9=[rsp+0x230]（输出槽，循环前被写 0）、第 5 参数=[rsp+0x50]。进入 sub

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-51063.jsonl, run-1314496.jsonl, run-1995778.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
