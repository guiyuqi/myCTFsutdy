# 41 · ez_pytorch

- **flag**: `0xGame{3z_p1ckl3_fOr_pyt0rch}`
- **提交**: code 200 / msg OK / result true
- **分类**: AI / 模型文件（离线题，无容器）
- **成品脚本**: `scripts/41-solve.py`

## 附件
`firmware/41_ez_pytorch/attach.zip` → `load.py` + `model.pth`

`load.py`:
```python
import torch
model = torch.load("model.pth", weights_only=True)   # <- 报错点
print("model loaded:", model)
# better experience: Python3.11+ torch >= 2.6
```

## 结论：`.pth` 是恶意 pickle，被 `weights_only=True` 白名单拦下

`model.pth` 其实是 **zip 容器**（torch 的 `_use_new_zipfile_serialization` 格式），
成员 `model/data.pkl` 是关键：

```
0: PROTO 2
2: GLOBAL '__builtin__ exec'
22: BINUNICODE "<payload source>"
1647: TUPLE1
1650: REDUCE          <- exec(<payload source>)
1653: STOP
```

`weights_only=True` 只允许 torch 白名单里的 GLOBAL，`__builtin__ exec` 不在其中，
所以加载直接报错 —— 这正是题目「加载脚本为啥报错」的答案。

## 安全做法（**没有**执行 pickle）

1. `zipfile` 读 `model/data.pkl`；
2. `pickletools.dis` / `pickletools.genops` 静态列出 opcode，**不 go through `pickle.load`**；
3. 从 `BINUNICODE` 操作数里直接抠出恶意源码，落盘 `work/41_pytorch/payload_recovered.py`；
4. 照抄源码里的 4 段解码逻辑自己重写一遍（不 exec 它）。

## 四段解码（`model/data/{0,1,2,3}`）

| 段 | 数据 | 算法 | 明文 |
|---|---|---|---|
| p0 | `data/0` (8B) | 循环 XOR，key `(0x5A,0xA3,0x3C)` | `0xGame{3` |
| p1 | `data/1` | 字符串反转后 base64 解码 | `z_p1ck` |
| p2 | `data/2` (14B) | hex 解码，再 `(b[i]-i) & 0xFF` | `l3_fOr_` |
| p3 | `data/3` | base64 解码，首字节 `^0xA5`，其后逐字节与前一位 XOR 链 | `pyt0rch}` |

拼接：`p0+p1+p2+p3` = `0xGame{3z_p1ckl3_fOr_pyt0rch}`

题目源码里还有一句提示：「如果你觉得逆向逻辑太难，那就去试试别的方法 :)」
—— 即直接 `exec` 这段 payload（危险，不要做）；或把 GLOBAL 白名单绕过后加载。
本解走纯静态路线，无需执行任何字节码。

## 复现
```bash
cd ~/ctf-2026 && python3 scripts/41-solve.py
```

## 防御要点（题目自带结论）
- pytorch 底层用 pickle，`__reduce__` 会被翻译成虚拟机指令 → `exec` / `os.system` 直接 RCE；
- 新版 torch 默认 `weights_only=True` 用白名单挡住恶意 GLOBAL；
- 最安全：改用 `safetensors`。
