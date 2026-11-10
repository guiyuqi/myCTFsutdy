# 容器政策 · 强网杯 2026 线上赛（人类指令实录）

> 存在理由：交接文档里"容器被冻结"长期是 **U1 未核实**（工作区 grep 不到任何落盘记录）。
> 这份文件把它变成**可引用的事实**，后来人不要再猜。

## 1. 人类指令时间线（原文口吻，不改写）

| 时间 | 指令 | 语义 |
|---|---|---|
| 2026-10-31 09:0x | 「现在依旧不要开容器，等我下指令」「Dreambound 容器先不起」 | 全面冻结 |
| 2026-10-31 10:2x | 「注意容器已经开了」+ 两张面板截图（Dreambound `nc <target> 26681`、ezphp `https://eci-2ze6bij3pcxb7tw62haw.cloudeci1.ichunqiu.com:443`） | **定向解冻**：这两道可用 |
| 2026-10-31 10:2x | 「web2 那一题队友也在做，如果涉及修环境这样的可能会影响队友的操作就不要动，让队友来」 | **ezphp 我方只读/不碰**，含"不要重启、不要改配置、不要刷接口" |

## 2. 当前容器状态（10:33 快照）

| 题 | 归属 | 地址 | 我方动作 |
|---|---|---|---|
| Dreambound `LrjaG__9f5MrXApw` | **我方**（父代理派人） | `nc <target> 26681` | 可攻。**不要点"重新下发"**（会重置状态）；要重置先问人类 |
| ezphp `xCn4gbGUPAea4Iw_` | **队友彭艺棋**（他解的题） | `https://eci-2ze6bij3pcxb7tw62haw.cloudeci1.ichunqiu.com:443` | **禁碰**。零请求、零改配置、零重启 |
| babystar / CanonicoPWN / hexachord | 未申请 | — | **冻结**，需人类明确指令才可申请（且要先腾配额，见 §3） |

## 3. 配额算术（关键，别踩）

`team_docker_limit=2`、`user_docker_limit=1`（`notes/methods/platform-qwb-ichunqiu.md` L40-41）。
当前**已开 2 个**（Dreambound + ezphp）⇒ **团队配额已满**：
再想开 babystar / CanonicoPWN / hexachord，必须先关掉一个（Dreambound 是我们的，ezphp 是队友在用的**不能关**）。
⇒ 实际上「新开一道题」= 「放弃 Dreambound」。这是人类的决定，不是代理的。

## 4. 唯一合法通道

`scripts/container-pool.py` 是唯一写者；`qwb.py docker` 与门禁插件会直接拒（硬规则 §3）。
不要让代理自己点面板的"重新下发 / 关闭 / 延时"。

## 5. 容器题的共同属性（`type_id=2`）

`is_dynamic_flag=1` ⇒ **flag 每队一版，只能从容器里拿**；网上/别人 WP 里的串**必然是错的**。
`answer_limit=0` 只对静态题（`is_dynamic_flag=2`，如 vmshare）意味着"可以拿平台当判据穷举"。

## 6. 2026-10-31 12:45 追加：第二批上题后的决定

第二批 13 题（12:30 上），其中 9 道是 `type_id=2` 容器题。
**人类决定：先都不开容器**（`container-pool.py status` 显示池内 0/4，此前 Dreambound/ezphp 的两台已过期）。

⇒ 因此以下题目**被动停摆**，不是我方能力问题：
- `crp-11741`（Crypto）：位流已完整反汇编成网表（`work/crp11741/out.fasm`，228 LUT + 1 BRAM，0 IOB / 无时钟 ⇒ 附件里没有可观测面），**必须有容器才能打 oracle**。
- `babyark` / `babysilent`（PWN，babystar 同系列）：容器才有服务端。
- `谍影重重7`（Misc 流量取证）：附件为空，pcap 应在容器侧。
- `frozen` / `HESEUS` / `BlindReview` / `vaultlink` / `Blackout` / `What The Fox!`：纯容器。

可继续推进的无容器题：`NeuronShuffle`（纯附件）、`oldsvr`（附件 + 已给远程 `<target>:1883`）、`fault_web_and_fault_hash`（已给 web 地址）。
