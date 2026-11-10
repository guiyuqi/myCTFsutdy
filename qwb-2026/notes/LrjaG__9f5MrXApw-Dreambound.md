# LrjaG__9f5MrXApw · Dreambound（强网杯 2026 线上赛 · Misc · 1000）

> 状态：**NOT_YET**（静态半边已做透；flag 不在附件里，须容器）
> 题面：`Try to dream hallucinate.`（容器题，附件 3.76 MB）
> 纪律：未申请容器、未提交 flag、未 `torch.load`。

---

## 1. 附件是什么（判类型，已确认）

下载落点（`scripts/qwb.py get LrjaG__9f5MrXApw --download`，走 OSS 直链）：

```
firmware/qwbLrjaG__9f5MrXApw_Dreambound/dreambound_e68e7a74dce1d2e83bf476b99bf37ea3.zip  3938504 B
└── dreambound/
    ├── checkpoint.pt     4245557 B   md5 c78bccefcc7649378393abe9b81448d0
    ├── model.py             1715 B
    └── requirements.txt       23 B   torch>=2.0 / numpy>=1.24
```

`checkpoint.pt` 是 **torch.save 的 zip 容器**（`checkpoint/data.pkl` + `data/0..17` + 版本元数据），
模型是一个 **DreamerV3 风格的微型 world model**（`model.py` 给全了结构）：

| 模块 | 形状 | 参数 |
|---|---|---|
| `gru`（GRUCell） | weight_ih (1152,5) / weight_hh (1152,384) / bias×2 | 446 208 |
| `decoder` | Linear 384→256 → ReLU → Linear 256→**4** | 98 564 |
| `reward_head` | 384→512→512→1 | 459 521 |
| `continue_head` | 384→128→1 | 49 281 |
| 合计 | | **1 059 718** |

`OBS_DIM=4, ACT_DIM=5, H_DIM=384`；`checkpoint` 根键只有 `config`（**空 dict**）与 `state_dict`。

## 2. 静态半边四条通道全部查过（结论：flag 不在文件里）

| 通道 | 做法 | 结果 |
|---|---|---|
| **反序列化** | 自写 restricted unpickler（只放行 `collections.OrderedDict` / `torch._utils._rebuild_tensor_v2` / `torch.FloatStorage` + `PERSID`），`pickletools.dis` 全 706 个 opcode 审一遍 | **干净**：只有 18 个 `_rebuild_tensor_v2`，`config` 是空 dict，无 `__reduce__` 恶意 global。`weights_only=False` 在这里只是作者的随手写法，不是洞口 |
| **元数据 / 尾部** | zip 条目对账（18 个 storage 全被 state_dict 引用，无孤儿）、EOCD 后 0 字节（无 appended data）、`_metadata` 空 | 无 |
| **位平面（权重 LSB）** | 逐 tensor 抽 float32 最低字节的直方图 / printable 比例 | 全部 ~37% printable = 均匀噪声，无 ASCII？否 → 无隐写 |
| **明文** | 整档 `strings -n6` + `grep -a 'flag{'` | **0 命中** |

权重统计（min/max/mean/NaN 全档）也跑了一遍：**无 NaN、无 inf**，18 个张量尺寸与 `model.py` 完全自洽。

## 3. 关键发现：作者只手工改过一处权重

对每个张量做「**float32 位级完全重复值**」审计（训练出来的权重极少位级完全重复）：

```
gru.weight_ih: [(-6.0, 384 次), (1.0, 384 次)]   ← 唯一异常
其余张量重复数 ≤3（纯 float32 舍入巧合）
```

定位到 `gru.weight_ih[:, 0]`（即**动作 0** 的输入列，GRU 门序 `[r|z|n]` 各 384 行）：

- `weight_ih[0:384, 0]   = -6.0`（常量）→ reset gate `r = σ(-6) = 0.00247 ≈ 0`
- `weight_ih[384:768, 0] = +1.0`（常量）→ update gate `z = σ(+1) = 0.7311`
- `weight_ih[768:1152, 0]` 未改（std 1.07）

⇒ 动作 0 被改造成一个**确定性的泄漏衰减原语**：
`h ← 0.7311·h + 0.2689·c`，其中 `c = tanh(W_in[:,0]+b_in)` 是常量（`r≈0` 把 h 项从 n 门里切断）。

对照其余动作列的自然幅度（`r/z` 门 ±0.1~0.5），**动作 2 的整列是自然训练出来的饱和门**：
`r` 门 ∈ [−4.26, +14.0] → `r≈1`；`z` 门 ∈ [−13.76, +0.75] → `z≈0`。

⇒ 动作 2 是**隐状态整体覆写原语**：`h ← tanh(W_in[:,2] + b_in + W_hn h + b_hn)`。

**动作 0（衰减/擦写）+ 动作 2（覆写/计算）构成一对「写—擦」原语**，这就是作者留下的机制入口：
用动作 2 可以把 384 维隐状态推到任意方向，用动作 0 可以按 27%/步 的确定比例泄漏回常量。
配合 `decode`（384→4 的线性+ReLU 读出），**模型可以被驱动到训练分布之外** —— 这正是题面
"hallucinate" 的字面含义。

## 4. 行为学验证（numpy 复现前向，无 torch）

`scripts/LrjaG__9f5MrXApw-static.py` 里重实现了 GRU 前向（PyTorch 门序 r/z/n），单动作迭代 200 步的
不动点：

| 策略 | 观测 `decode(h)` | reward | continue | ‖h‖ |
|---|---|---|---|---|
| a=4 ×200 | `(0.998, 0.996, -0.001, -0.001)` | +3.61 | +19.9 | 4.45 |
| a=3 ×200 | `(1.072, 0.993, -0.038, 0.011)` | +2.57 | +29.1 | 6.47 |
| a=1 ×200 | `(0.978, 1.203, 0.185, -0.048)` | −1.67 | +27.1 | 6.90 |
| a=0 ×200（被改的那支） | `(1.401, 1.072, 0.755, 0.498)` | +0.08 | +6.36 | 11.74 |
| **a=2 ×200（覆写）** | **`(6.221, 4.929, 6.092, 6.046)`** | −6.81 | **−1.81** | 15.00 |

两个可读信号：

1. **分布内**不动点收敛到 `obs ≈ (1, 1, 0, 0)`（"到达目标并停住"的形状），说明训练数据是一个
   4 维观测 / 5 动作的小环境（位置+速度 / 四向+空操作是常见配置），reward head 在分布内为正。
2. **分布外**（只按动作 2）观测跑到 `(6.2, 4.9, 6.1, 6.0)`、reward 转负、**continue head 掉到 −1.8**
   ⇒ 模型自己判定"这个梦不该继续"。这就是**幻觉/hallucination 的可判定特征**。

随机策略 32 步的 reward 区间是 `[−18.2, +23.5]`，`continue` 在 `[−1.1, +31.6]`，说明这两个 head
输出的是 logit 而非概率。

## 5. 为什么判定「须容器」

- 附件里**没有 server 代码**，只有模型权重 + 前向定义 —— 交互协议（收什么、回什么、什么条件给 flag）
  完全在容器侧。
- flag 不在文件里（第 2 节四路并查 + 第 3 节全量重复值审计均已排除），也不在 pickle 里。
- 唯一的手工改动（动作 0 的门值）指向的是**运行时**能力（可编程地写/擦隐状态），不是静态载荷。

### 一旦拿到容器，第一步（已备好）

1. `nc` 连上**只读**抓 banner 一次，确认协议是哪一种：
   - (a) **批量**：提交长度 T 的动作序列 → 返回 T 步 obs/reward/continue；
   - (b) **逐步**：每步发一个动作 → 返回 obs，像真 env 一样；
   - (c) 其他（要求提交观测 / 目标 / 上传文件）。
2. 只要拿到 (a)(b) 任一种，立刻用 `scripts/LrjaG__9f5MrXApw-static.py`（同一份权重的 numpy
   复现）**离线**对齐服务端输出 —— 对齐 = 协议确认 + 本地可无限搜索。
3. 然后用「动作 2 覆写隐状态 + 动作 0 泄漏」把 `decode(h)` 逼到目标观测（对 h 做梯度优化即可，
   因为 decode 是 ReLU 网络、h 可被动作 2 自由写），观察服务端在哪个观测上给 flag。
4. 若 banner 直接给了目标观测/目标 reward，那就是**离线可解**的：本地搜索动作序列，
   拿到序列后一次提交即可，不必反复连容器。

**需要的容器**：Dreambound 的靶机（host:port）。不需要额外的数据库/文件服务。
若队长更省事，直接要**服务端源码或镜像**也行 —— 有了 server 代码这一步就变成纯离线题。

## 6. 复现

```bash
cd ~/ctf-2026 && source ~/re-tools/fw-env.sh
python3 scripts/qwb.py get LrjaG__9f5MrXApw --download
cd work/LrjaG__9f5MrXApw_dreambound && unzip -o ../../firmware/qwbLrjaG__9f5MrXApw_Dreambound/*.zip
python3 ../../scripts/LrjaG__9f5MrXApw-static.py                 # 审计 + 不动点
python3 ../../scripts/LrjaG__9f5MrXApw-static.py --acts 2@400    # 任意动作序列 rollout
```

证据：`evidence/LrjaG__9f5MrXApw-static.log`（文件类型/尺寸/md5/zip 条目/全张量统计/grep 结果）。

## 7. BLOCKED

`BLOCKED: 需要 Dreambound 容器（host:port）或服务端代码。attach 侧静态通道已全部穷尽（反序列化/元数据/尾部/位平面/明文，四路皆空），flag 不在 artifact 内。`
