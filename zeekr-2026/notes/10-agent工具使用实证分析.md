# Agent 解题能力分析（基于 21 个 session 的工具使用实证）

- 分析对象: `~/.dsh/sessions/<session-store>/` 下 21 个 session
- 数据量: 9,298 事件 / 1,787 次工具调用 / 1,536 次 bash 执行
- 方法: 解析 `tool/call` 的**实际命令**（非文本关键词，避免被 `fw-env.sh` 回显污染）
- 说明: 1 个 session（04894359）是赛前环境搭建，其余 20 个为解题过程

---

## 一、结论速览

**赛前配置的 CTF 专业工具链，基本没被用。**

agent 的实际工作方式是：**用 `bash` 调 `python3` 现写脚本**（140 次），
配合标准库 `hashlib` / `struct` / `PIL` / `numpy` 解题，而不是调用现成的逆向工具。

---

## 二、工具层使用（DSH 工具）

| 工具 | 调用次数 | 占比 |
|---|---|---|
| `bash` | **1,536** | **85.9%** |
| `read_image` | 57 | 3.2% |
| `read` | 57 | 3.2% |
| `write` | 46 | 2.6% |
| `present` | 27 | 1.5% |
| `edit` | 18 | 1.0% |
| `job_output` | 15 | 0.8% |
| `web_search` | 13 | 0.7% |
| `todo_write` | 7 | 0.4% |
| **`skill`** | **6** | **0.3%** |
| 其他（ask_user_question/code_outline/...） | 5 | 0.3% |
| **MCP 工具（`rea_*` 等 116 个）** | **0** | **0%** |

**工具调用成功率 99.7%**（1,787 次仅 5 次失败：`code_outline` 1、`read_image` 1、`write` 1、`bash` 2）。

---

## 三、核心发现：CTF 工具链实际执行情况

我赛前配置的工具，**真正被执行的只有 3 个，且各只在 1 个 session**：

| 工具 | 实际执行 | 判定 |
|---|---|---|
| `fw-decompile`（我写的反编译封装） | 3 次 / 1 session | ⚠️ 仅试过 |
| `unsquashfs` | 5 次 / 1 session | ⚠️ 仅试过 |
| `qemu-mipsel-static` | 4 次 / 1 session | ⚠️ 仅试过 |
| `docker` | 15 次 / 2 session | ⚠️ 少用 |

**从未执行的工具：**

| 工具 | 状态 |
|---|---|
| `binwalk` | ❌ 0 次 |
| `rizin` / `radare2` / `r2` | ❌ 0 次 |
| `angr` | ❌ 0 次 |
| `z3` | ❌ 0 次 |
| `lief` / `capstone` / `unicorn` / `pwntools` / `pyelftools` | ❌ 0 次 |
| `sasquatch`（非标准 squashfs） | ❌ 0 次 |
| `jefferson`（JFFS2） | ❌ 0 次 |
| `ubireader_extract_images` / `_files`（UBI） | ❌ 0 次 |
| `analyzeHeadless`（Ghidra headless） | ❌ 0 次 |
| `qemu-arm-static` / `qemu-aarch64-static` / `qemu-i386-static` | ❌ 0 次 |

> 注意：我之前用「关键词出现次数」统计时这些数字虚高（`fw-decompile` 169 次、
> `ghidra` 191 次），**原因是 `fw-env.sh` 每次被 source 都会打印工具清单**。
> 解析实际命令行后才得到上述真实数字。这是本次分析最重要的方法修正。

---

## 四、Skill 使用：6 次，且有错配

| session | 调用的 skill |
|---|---|
| 5509f1d3 | `ctf-sandbox-orchestrator` |
| 5509f1d3 | `competition-custom-protocol-replay` |
| e47ea3cd | `ctf-sandbox-orchestrator` |
| ebb6caa3 | `firmware-pentest` |
| fbc81842 | `ctf-sandbox-orchestrator` |
| fbc81842 | `competition-jwt-claim-confusion` ← **错配** |

可用 skill **87 个**，调用 6 次（0.3%）。

**问题**：
1. `ctf-sandbox-orchestrator` 被调 3 次（说明 agent 知道它是入口），但**后续没有按
   路由走**——应该路由到 `competition-firmware-layout`，却调了 JWT 和协议重放。
2. `competition-jwt-claim-confusion` 是 **JWT 主题，固件赛里没有 JWT 题**——明显误选。
3. 最贴题的 `competition-firmware-layout`（固件布局/分区/启动链）**一次都没调**。
4. `firmware-pentest` 只在 1 个 session 调过。

---

## 五、agent 实际靠什么解题

### 5.1 命令模式（1,536 次 bash 的首词分布）

| 首词 | 次数 | 典型用法 |
|---|---|---|
| `cd` | 1,009 | 切目录 + 组合命令 |
| **`python3`** | **140** | **heredoc 现写脚本解题** |
| `ls` / `cat` / `find` / `grep` | 143 | 信息搜集 |
| `for` / `echo` / `sed` | 97 | 批处理与摘要 |
| `timeout` + `nc` | 27 | 连远端靶机 |
| `source` | 25 | 激活环境（`fw-env.sh`） |

### 5.2 自写 Python 脚本用到的库

| 库 | 次数 | session 数 | 说明 |
|---|---|---|---|
| **`PIL`** | **217** | 9 | 图像取证（多道题涉及色卡/照片/位矩阵） |
| **`numpy`** | **182** | 10 | 数值/矩阵运算 |
| **`hashlib`** | **73** | 12 | SHA-256 等哈希构造 |
| `struct` | 26 | 8 | 二进制打包解析 |
| `cryptography` | 23 | 4 | ECDSA 验签/签名伪造 |
| `zlib` | 5 | 4 | 解压 |
| `hmac` / `scipy` / `zstandard` | 少量 | 2~3 | |
| `capstone`/`angr`/`lief`/`pwn` | **各 1** | 1 | 试了一下就弃用 |
| `unicorn` / `z3` / `elftools` / `pycryptodome` | **0** | 0 | 完全没用 |

### 5.3 命令级错误信号（被"工具成功"掩盖的真实失败）

| 信号 | 次数 |
|---|---|
| `Traceback` | 45 |
| `No such file` | 31 |
| `ModuleNotFoundError` | 10 |
| `Timeout` | 10 |
| `SyntaxError` | 6 |
| `NameError` / `FileNotFoundError` | 8 |
| `Read-only file system` | 11（**全部来自赛前环境搭建那个 session**，非解题过程） |

---

## 六、能力画像

### 长处

1. **端到端自足**：不依赖现成工具，能自己写解析器/求解器把题做出来（11/11 全解出）
2. **密码学与二进制处理扎实**：`hashlib` + `struct` + `cryptography` 组合覆盖面广
3. **图像/数值处理能力强**：`PIL` 217 次 + `numpy` 182 次，说明这类题（色卡解码、
   位矩阵、坐标变换）是它的舒适区
4. **工具调用可靠**：99.7% 成功率，几乎不浪费轮次在失败调用上
5. **信息搜集自觉**：`read`/`grep`/`find`/`strings` 用得充分
6. **交付规范**：27 次 `present` 产出解题笔记 + 可复现脚本 + 运行日志

### 短处

1. **不查工具清单**：赛前配了 34 架构 qemu、Ghidra、angr、各类解包器，
   它**基本没试过**就直接手写 Python。等于工具链白配。
2. **skill 系统形同虚设**：87 个可用，用了 6 次（0.3%），其中 1 次还是错配主题。
   最贴题的 `competition-firmware-layout` 零调用。
3. **不会"先侦察可用工具再开工"**：没有出现 `command -v` / `ls ~/re-tools/bin`
   这类"盘点我有什么"的动作，直接进入解题。
4. **反复试错成本**：45 次 `Traceback` + 6 次 `SyntaxError`，说明是"写完就错、
   错了再改"的模式，而非先想清楚再写。
5. **未利用 MCP**：116 个 rea 逆向工具（`batch_decompile`、`analyze_function` 等）
   **零调用**。

### 需要修正的归因（避免误判）

- **不能说"工具没用所以是浪费"**：本次题目以**协议逆向 + 密码学 + 图像取证**为主，
  这类题手写 Python 确实是最短路径，`angr`/`rizin` 未必更快。
- **同理不能说"手写 Python 就是最佳"**：如果是路由器固件解包、异构架构仿真类题目，
  不用 `qemu`/`sasquatch` 会非常吃力。
- **真正的问题是"不盘点、不试"**：不是选择了错误的工具，而是**没有做选择这个动作**。

---

## 七、给后续题目的可操作建议

1. **强制开工前盘点**：在任务开头加一步「`ls ~/re-tools/bin` + `command -v` 关键工具」，
   让 agent 知道有什么可用。
2. **skill 要显式点名**：不要指望 agent 自己选。在提示词里直接写
   「用 `competition-firmware-layout` 分析」比让它自由发挥可靠得多。
3. **固件类题必须先尝试工具链再手写**：`unsquashfs` → `sasquatch` → `jefferson`/`ubi` 的顺序
   应固化成流程，而不是上来就写 Python 解析器。
4. **AGENTS.md 里加"工具优先级"**：明确"先试现成工具，失败再手写"，
   并列出常用工具清单。
5. **MCP 需要显式触发**：如「用 `rea_batch_decompile` 反编译这个函数」。

---

## 附：本分析使用的方法（可复用）

```python
# 关键：解析 tool/call 的实际命令，而不是搜全文关键词
# 全文关键词会被 fw-env.sh 的回显污染（工具清单每次 source 都打印）
for line in zstd_stream(session.v3.jsonl.zstd):
    o = json.loads(line)
    if o["type"] == "tool/call" and o["data"]["name"] == "bash":
        cmd = json.loads(o["data"]["arguments"])["command"]
        # 用行首/管道/分号边界匹配可执行名，避免匹配到回显文本
```
