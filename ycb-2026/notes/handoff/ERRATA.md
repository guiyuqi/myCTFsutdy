# 勘误表（2026-10-24 复核）

> 复核对象：本目录 `README.md` / `METHODS.md` / `CTF-FRAMEWORK-SPEC.md` / `prompts/**`，
> 以及 `~/ctf-2026/notes/POST-MORTEM-YCB2026.md`、`notes/ARCHITECTURE-PROPOSAL.md`、`notes/12084-*.md`。
>
> **方法**：不引用二手结论，直接复算 DSH 会话日志
> `~/.dsh/sessions/--home-fragranstea-ctf-2026--/session-e3f62776-…/session.v3.jsonl.zstd`。
> 复现：`python3 ~/ctf/templates/ctf-kit/recompute.py`（依赖 `pip install zstandard`）。
>
> **原则**：原文一律保留，只在出错处加 `⚠️ 勘误` 标记并指向本表。原文不该被删——
> 错在哪比"改对了"更有信息量。
>
> 备份：改动前的完整副本在 `~/ctf-2026/work/handoff.bak-20261024/`。

---

## A. 已证伪（事实错误，有复算依据）

### A1 「14:00–15:00 有 1 小时空窗」——不成立

| | |
|---|---|
| 原文位置 | `work/handoff/METHODS.md:71`、`prompts/skills/timebox-park.md:20`、`notes/POST-MORTEM-YCB2026.md:133` 与 `:212`、`notes/ARCHITECTURE-PROPOSAL.md:86` |
| 复算结果 | **14:00–15:00 有 43 次工具调用**；13:00–15:30 共 243 次。<br>该小时内最长静默 **16.7 分钟**（14:06:48 → 14:23:28）。<br>整个窗口最长静默 **23.9 分钟**（14:36:47 → 15:00:40），**恰好到赛事结束**。 |
| 正确表述 | "14:00–15:00 有 43 次工具调用，没有整小时空窗；期间有一次 16.7 分钟的停顿。真正的静默是 14:36 之后停止作业，直到 15:00 赛事结束。" |
| 为什么必须改 | 原句把"没有产出新题"误诊成"没有作业"。按它做复盘会得出"我们输在松懈"，从而把资源投到错误的方向；实际那小时在推 12073 和清理 WP。**这条也是"投入与产出负相关"的一部分证据，不是反证。** |

> 附带更正：另一份会话复盘说"14:00–14:26 一直在推 12073"。复算显示这 26 分钟里存在 16.7 分钟的静默（14:06→14:23），**"一直在"也不准确**；准确说法是"该时段有 43 次调用，含一次 16.7 分钟停顿"。

### A2 「本包不含代码」——不成立

| | |
|---|---|
| 原文位置 | `work/handoff/README.md:3` |
| 实际内容 | `12068/main.exe`(89 KB)、`12068/win_server.exe`(80 KB)、`12068/12068-solve.py`(19 KB)、`12070/BabyMenuKit.ps1`(24 KB)、`12070/BabyMenuProbe.ps1`(9.5 KB)、`12070/BabyMenuProbe.ps1.b64`(12.7 KB) |
| 正确表述 | "本包含需求/架构/方法/提示词，**外加两题的二进制与利用脚本**（12068/12070）。" |
| 附带发现 | `handoff/12068/main.exe` 与 `work/12068_lms/main.exe` **sha256 完全相同**（`d5dcd13c…`），是重复搬运；且 `handoff/12084/` 是**空目录**，而 `notes/12084-千千的咲.md`(654 行) 与 `work/12084_qiqian/` 是全套材料——交接时漏了。 |

### A3 「本机无外网（所以 astcenc 装不上）」——现在不成立

| | |
|---|---|
| 原文位置 | `notes/12084-千千的咲.md:200` |
| 复算结果 | 2026-10-24 实测 `pip download` / `pip install` 成功（texture2ddecoder、reportlab 均已装上）；网络可用。 |
| 正确表述 | "当时可能确实断网；以 2026-10-24 实测为准，外网可用。astcenc 另因 GitHub 下载超时未装成（1.3/3.6 MB 断开两次），已有降级方案。" |

---

## B. 不可按原样使用（不是"错"，是"会静默失效"）

### B1 Skills 2.0 的 frontmatter 字段会被**静默丢弃**

| | |
|---|---|
| 原文位置 | `prompts/skills/*.md` 的 9 个文件（`when:` / `bind_tools:` / `acceptance:` / `failure_modes:` 都在**顶层**） |
| 核实结论 | `dsh-skill-filesystem` 的解析器只取 `name` / `description` / `whenToUse` / `metadata` / 两个 invocation 布尔值；**顶层未知键既不报错也不保留**（`parseSkillFile` → `optionalMetadata` 只读 `data.metadata`）。 |
| 后果 | 按现文件装进 DSH，技能只剩名字和一句话描述；`bind_tools`/`acceptance` 全部消失 = R6（技能绑定工具与验收）等于没实现，而且**不会有任何报错**。 |
| 修法 | 把这些字段整体塞进 `metadata:` 子对象；`when:` 改成 `whenToUse:`。示例见本目录 `prompts/skills/_template.dsh.md`。 |

### B2 「gate 作为 command hook」是三个可选方案里最弱的一个

| | |
|---|---|
| 原文位置 | `CTF-FRAMEWORK-SPEC.md:49`、`:60` |
| 核实结论 | ① `dsh-hooks-claude-code` 的 `SubagentStart`/`SubagentStop` 上报的 `agent_type` **恒为 `general-purpose`**，拿不到"这是 Planner 还是 Solver"，SPEC 的 R-2 在 hook 层做不出来；② hook 每次工具调用起一个子进程；③ 桥的 README 自己写着：定制行为应用原生插件（"no hook protocol in between"）。 |
| 更好的落法 | 原生 Cordis 插件 + `ctx.tools.guard()`（**单调**，排在 `tools/pre-execute` 之后，"no later listener can turn that denial back into permission"）；**R6 的"越界拒"改成"看不见"**——`agent.ctx` 作用域下注册的工具只对该 agent 可见（"one agent sees a different prompt and tool set than its neighbors"）。 |

### B3 「后台 job 绕过 PreToolUse」——机制说错了，结论对

| | |
|---|---|
| 原文位置 | `CTF-FRAMEWORK-SPEC.md:126`（R-3） |
| 核实结论 | 后台 job 里的每一条命令仍然是一次工具调用，`tools/pre-execute` 看得到，**不存在绕过**。真正的软肋是：该钩子**刻意不允许改写 `exec.arguments`**（否则日志/渲染与实跑脱节），所以"禁止用裸 shell 做高风险动作"只能靠正则黑名单。 |
| 正确表述 | "去掉万能 shell 的理由不是'gate 看不见'，而是'gate 只能 deny、不能 sanitize'——黑名单在赛事压力下等于建议。" |

---

## C. 曾被质疑、复算后**成立**（不要误删）

### C1 「pyzipper 已装却手写 20 行 HMAC」——成立

复算：`pyzipper` 在 `~/re-tools/pylibs`，`source ~/re-tools/fw-env.sh` 后 `import pyzipper` 成功。
2026-10-24 的复核过程中一度判定"没装"，原因是**没激活 fw-env.sh**，属复核方误判，已更正。
这条恰恰是"工具没被想到"的**有效证据**，不要因为曾被质疑就删掉。

### C2 「6 次不可解」——成立

`notes/POST-MORTEM-YCB2026.md` 附录 B 逐条列了 6 次（12062×2、12079、12086、12073×2，含 1 次假 SOLVED）。
正文摘要写"5 次"是按"不同题"计（12079/12073 各计一次），口径不同，不是矛盾。

---

## D. 口径问题（无对错，但会让决策偏）

### D1 「约 60–70% 损耗是架构可消掉的」

| | |
|---|---|
| 原文位置 | `notes/ARCHITECTURE-PROPOSAL.md:21` |
| 问题 | 这是估值，且分母两可。**按题算**：真正能被架构救回的只有 3–4 道（12065 资源误判、12075/12076 无 revisit、12062 重扫）。**按墙钟算**：49.6% 的回合时间落在 13 个"回合内轮询"的 turn 里。两个数都真，但含义完全不同。 |
| 建议表述 | 换成可测的那句："墙钟的 49.6%（108.2/218.3 分钟）花在同一类行为（回合内 sleep+轮询）上。" |

### D2 回放验收选 12080 / 12086

| | |
|---|---|
| 原文位置 | `CTF-FRAMEWORK-SPEC.md` §5 |
| 问题 | 这两题是**成功案例**且可离线复算，重走一遍验证不了要治的病：它们没有环境压力，也不会诱使 agent 下负结论。 |
| 建议 | 改用 12062 / 12073 回放，并**伪造一个 `已答出N次 > 0` 的 detail**——这样"判据三重对照"和 verifier 才有东西可拒。验收标准应是"框架拒绝了我多少次"，不是"框架又解出了一次"。 |

---

## 复现方式（每行可直接跑）

```bash
pip install zstandard
python3 ~/ctf/templates/ctf-kit/recompute.py      # 主会话全部关键数字
# 期望输出片段：
#   turn 数           97
#   >20 次调用的 turn  13 个，吃掉 108.2 / 218.3 分钟 = 49.6%
#   14:00–15:00        43 次工具调用（'一小时空窗' 这个说法 不成立）
#   压缩时刻           10-24 12:18:43
#   全 session skill 调用 98

# 精确到秒的静默窗口
python3 - <<'PY'
import datetime as dt, json, os, sys, zstandard
p=os.path.expanduser('~/.dsh/sessions/--home-fragranstea-ctf-2026--/session-e3f62776-34c2-4adc-b921-b1546f55310f/session.v3.jsonl.zstd')
raw=zstandard.ZstdDecompressor().stream_reader(open(p,'rb')).read().decode('utf-8','replace')
d=json.JSONDecoder(); i=0; evs=[]
while i<len(raw):
    while i<len(raw) and raw[i] in ' \r\n\t': i+=1
    if i>=len(raw): break
    try: o,j=d.raw_decode(raw,i); evs.append(o); i=j
    except Exception:
        n=raw.find('\n',i); i=(n+1) if n>=0 else len(raw)
calls=sorted(int(e['time']) for e in evs if e.get('type')=='tool/call')
T=lambda ms: dt.datetime.fromtimestamp(ms/1000)
h=[t for t in calls if T(t).strftime('%m-%d %H')=='10-24 14']
print("14 点那一小时调用数:", len(h))
print("该小时最长静默: %.1f 分钟"%max((h[k+1]-h[k])/60000 for k in range(len(h)-1)))
PY
```

## 与本次复核相关的修正清单（按可信度排序）

| 级别 | 内容 | 处置 |
|---|---|---|
| ✅ 已修 | `md2pdf.py` 依赖 reportlab（不是 pandoc）；reportlab 已装进 `~/re-tools/pylibs` | 交付管线现在与题目 venv 解耦 |
| ✅ 已装 | `texture2ddecoder`（含 `decode_astc`） | ASTC 不再只能靠 WebGL 绕 |
| ⚠️ 未完成 | `astcenc`（GitHub 连续两次超时） | 有降级；不影响开赛 |
| ⚠️ 未完成 | Android emulator + system image | 无降级；动态移动题会归零，待你决定 |
| ⏸ 搁置 | Windows VM 接入（镜像在 `firmware/ycb-BabyMenu/Win11 x64 26h1/`；上次崩溃原因：从 `\\wsl.localhost\` 跑 28 G vmdk，`vmware-vmx` 0xc0000005） | 复制到本地 NTFS 盘再开即可 |
