# FLAGS · 提交结果汇总（台账口径）

> **本文件由台账生成，赛后以此为准。**
> 数据源：`evidence/submit-log.jsonl`（生成时 **118** 条记录，首条 2026-10-25T16:19:29+08:00，末条 2026-10-31T09:43:48+08:00）。
> 生成方式：脚本直接读台账统计，**无手填数字**；复现命令见文末 §复现。
> 本文件**只记状态，不记任何 flag 串**；flag 值以平台/台账为准。

## 一、统计（台账实测）

**已通过 0 / 被拒 1 / 未解出 10**（题单 11 道，来源 `work/TEAM-BOARD.md`）

| 口径 | 题数 | 台账依据 |
|---|---|---|
| 已通过 | **0** | 台账中 `result: true` 的记录共 **0** 条 ⇒ 全 118 条记录里没有任何一条通过 |
| 被拒 | **1** | 有提交记录但无 `result: true`：`brz2pZwJzt8gV8r6`（117 条） |
| 未解出 | **10** | 台账里**没有任何提交记录**的题（见下表） |

## 二、题目状态表

| 题号 | 题名 | 状态 |
|---|---|---|
| `Ik_y7i9Zazs2MsSc` | cwp | ⬜ 未解出 |
| `brz2pZwJzt8gV8r6` | vmshare | ❌ 被拒 |
| `q_uR0lUcyOA504fO` | easytl | ⬜ 未解出 |
| `Q3uU57zD-jL_MLaH` | ELFStudy | ⬜ 未解出 |
| `InT2P9luOG_Em_Ee` | hoRRibleRing | ⬜ 未解出 |
| `KVlvgNuOwJXPAyAQ` | 宇宙微波背景辐射 | ⬜ 未解出 |
| `__vwNhULhZSlz4Fa` | babystar | ⬜ 未解出 |
| `LrjaG__9f5MrXApw` | Dreambound | ⬜ 未解出 |
| `32iLx4SEkhDjnVUL` | CanonicoPWN | ⬜ 未解出 |
| `zI4b42E9skdT1U4m` | hexachord | ⬜ 未解出 |
| `xCn4gbGUPAea4Iw_` | ezphp | ⬜ 未解出 |

## 三、被拒明细（vmshare）

- 提交 **117** 次，`result: true` **0** 次 ⇒ **0 条通过**。
- 平台返回分布：「答案错误」104 条；「对不起，您的操作太过频繁」13 条。
- 其中 `result` 为空（限流/网络异常，既非通过也非否定）**1** 条。
- 结论：该题**未通过**。算法侧已解出唯一密钥，但题面 flag 串存在 256 个等价前像，逐类提交全部「答案错误」⇒ 当前无法确定哪一个会被平台接受。

## 四、口径与已知边界（读表前必看）

1. **已通过** = 台账里该题存在 `result: true` 记录（唯一判据；不看"应该能过"）。
2. **被拒** = 台账有该题提交记录，但全部非 `result: true`（含「答案错误」「操作太过频繁」「网络失败」）。
3. **未解出** = 台账无该题任何提交记录。注意它包含"**没提交**"，不等于"**已确认不可解**"，两者不能混写。
4. ★ **cwp（`Ik_y7i9Zazs2MsSc`）特别说明**：平台侧该题已解出（`work/TEAM-BOARD.md` 记录平台 88 队解出、本队由队友「彭艺棋」解出），但**我方台账对该题 0 条记录** ⇒ 按"台账为骨"口径**仍记为未解出**。补到 `result:true` 证据之前，不得改记为已通过。
5. ★ **台账仍在增长**：提交执行代理仍在写 `evidence/submit-log.jsonl`。本文件是**快照**，交付前重跑 §复现 刷新数字。
6. 台账首条是连通性测试（题号 `9999`，假 flag + 网络失败），**不计入任何题**，已从上表剔除。

## 五、复现（一条命令重算本文件所有数字）

```bash
cd ~/ctf-2026 && python3 - <<'EOF'
import json, collections
recs=[json.loads(l) for l in open('evidence/submit-log.jsonl',encoding='utf-8') if l.strip()]
by=collections.defaultdict(list)
for r in recs: by[str(r.get('id'))].append(r)
print('记录', len(recs), '| result:true 条数', sum(1 for r in recs if r.get('result') is True))
print('已通过题:', sorted({i for i,rs in by.items() if any(x.get('result') is True for x in rs)} - {'9999'}))
print('被拒题:', {i: len(rs) for i,rs in by.items() if i!='9999' and not any(x.get('result') is True for x in rs)})
EOF
```

> 配套自检：`python3 scripts/wp-check.py`（wp.md ↔ 台账逐字节对账）；`python3 scripts/wp-pack.py --dry-run`（支撑矩阵；0 道已解出题退 5 红灯）。
