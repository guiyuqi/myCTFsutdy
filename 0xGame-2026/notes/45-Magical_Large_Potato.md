# 45 · Magical Large Potato!

- **flag**: `0xGame{MLP_1s_s0_m4g1c}`
- **分类**: AI / 模型逆向（离线题，无容器）
- **分值**: 900 | 解出 5 人
- **提交**: `code=200, msg=OK, data.result=true` ✅
- **成品脚本**: `scripts/45-solve.py`
- **证据**: `evidence/45-solve-run.txt`

## 附件

`firmware/45_Magical_Large_Potato/Magic_Large_Potato.zip`
→ 单个文件 `Magic_Large_Potato.pth`（339310 B），`file` 认出是 **Zip archive**
（torch ≥1.6 的 `torch.save` 就是 zip 容器，不是旧式 pickle）。

zip 内清单：

```
Magic_Large_Potato/data.pkl          1098 B    <- state_dict 的 pickled 元数据
Magic_Large_Potato/data/0..8                    <- 9 个裸 float32 storage
Magic_Large_Potato/byteorder         "little"
Magic_Large_Potato/.format_version   1
Magic_Large_Potato/version           3
```

## 结构分析

`python3 -m pickletools .../data.pkl` 直接可读，没有混淆、没有恶意 `__reduce__`。
顶层是一个 dict，两个 key：

- `magic1` = `OrderedDict`，就是 state_dict：

  | 参数 | shape | storage | 说明 |
  |---|---|---|---|
  | `embedding.weight` | (23, 32) | data/0 (2944 B) | 23 个 32 维查询向量 |
  | `deep_mlp.0.weight/bias` | (128, 32) / (128,) | data/1,2 | `Linear(32→128)` |
  | `deep_mlp.2.weight/bias` | (256, 128) / (256,) | data/3,4 | `Linear(128→256)` |
  | `deep_mlp.4.weight/bias` | (128, 256) / (128,) | data/5,6 | `Linear(256→128)` |
  | `deep_mlp.6.weight/bias` | (100, 128) / (100,) | data/7,8 | `Linear(128→100)` |

- `magic2` = **23** —— 正好等于 `embedding.weight` 的行数，也正好等于 flag 长度。

关键观察：**最后一层输出维度 100 == `len(string.printable)`**
（`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_\`{|}~ \t\n\r\x0b\x0c` 共 100 个字符）。
`deep_mlp.{0,2,4}` 与 `{2,4,6}` 之间没有 norm 参数，因此 `1/3/5` 是纯激活函数。

## 解法

「魔法大土豆」= 一个被训练过的字符分类器：给它第 `i` 个查询（`magic2=23` 个愿望之一），
它吐出第 `i` 个字符在 100 个可打印字符上的分布。把 23 个 embedding 行全部喂进 MLP、
对 100 维输出取 argmax，可打印字符表下标即还原 flag：

```python
h = embedding.weight                      # (23, 32)
for i in (0, 2, 4, 6):
    h = h @ W[f'deep_mlp.{i}.weight'].T + b[f'deep_mlp.{i}.bias']
    if i != 6:
        h = np.maximum(h, 0)              # ReLU
flag = ''.join(string.printable[i] for i in h.argmax(1))
# -> 0xGame{MLP_1s_s0_m4g1c}
```

**激活函数不影响结果**：`relu` / `tanh` / 无激活 三种都得到同一个字符串；
只有 `sigmoid` 退化成全 `0`（因为权重尺度小、全落在线性区，与题目无关）。
`relu` 下 argmax 的**最小置信间隔 10.32 logits**（最大 11.45），判定毫无歧义。

## 复现

```bash
cd ~/ctf-2026
python3 scripts/45-solve.py            # 自动定位 zip 附件；也可直接传 .pth 路径

magic2 (n_queries) = 23
min argmax margin  = 10.3167  (logit units)
FLAG: 0xGame{MLP_1s_s0_m4g1c}
```

`scripts/45-solve.py` **不依赖 torch**（环境里没装，也不允许装）：
自己用 `pickle.Unpickler` 子类 + `persistent_load` 回放 `FloatStorage`，
再按 pickle 里的 `(offset, size, stride)` 用 `np.lib.stride_tricks.as_strided` 还原张量，
只靠 numpy 完成推理。

## 排除的方向（记录一下省得重走）

- pickle 里没有 `__reduce__` / `os.system` / `eval`，**不是 pickle RCE 题**；`strings | grep flag` 无命中。
- 权重里没有明文 flag（全 float32，无异常字节）；不是 stego。
- 不存在对模型的训练/梯度反演需求 —— 直接前向 + argmax 即可，属于"背答案"型模型。
- 没有 `tokenizer`/`vocab.json`/`config.json`，不需要猜 BPE。

## 提交

```bash
cd ~/ctf-2026
python3 scripts/ctfplus.py submit 45 '0xGame{MLP_1s_s0_m4g1c}'
# {"code": 200, "msg": "OK", "data": {"result": true}}
```
