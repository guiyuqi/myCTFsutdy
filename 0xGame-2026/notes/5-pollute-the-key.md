# 5 · pollute the key (Web, 833 → 685, 动态环境)

- **flag**: `0xGame{a0205ff7-e61b-47f1-abad-a0ad75ff570f}` ✅ SOLVED
- **flag 出处**: 容器内 `env FLAG` 与 `/app/flag.txt` 一致（RCE 以 `uid=0(root)` 执行）
- **提交**: `{"code": 200, "msg": "OK", "data": {"result": true}}`（`scripts/ctfplus.py log` 可查）
- **成品利用脚本**: `scripts/5-solve.py`（已含竞态逻辑，直接可重跑）
- **本地验证**: `work/5_pollute/verify_chain.py`(端到端)、`work/5_pollute/local_server.py`(可打的本机替身服务)
- **证据**: `evidence/5-pollute-the-key-live.log`、`evidence/5-pollute-the-key-verify.log`

## 0. 实战经过（关键，别踩的坑）

第一次打 live 容器时 `scripts/5-solve.py` 单发失败（`/api/order/list` 403），排查出两个只有真机才暴露的问题：

1. **`rotate_flag` 会秒回滚 SECRET_KEY**。现象很迷惑：污染响应里**重签的 cookie 用我们的值验签成功**，但下一个请求就不认了。
   连环境变量都给了答案：`FLAG_INTERVAL=31536000` —— 就是"周期性轮换 key"。
   解法：后台线程持续重新污染，同时循环发伪造 admin 请求，撞进时间窗。
   实测在持续污染循环下 **100/100 次**伪造 admin 请求返回 200。`/api/order/list` 单发必 403，是竞态不是死路。
2. **Python 版本不一致导致 marshal 报错**。worker 是 **Python 3.10.21**，我本机是 3.14，
   原来用 `marshal.dumps(compile(...))` 的 payload 在真机报
   `购物车数据无法解析: bad marshal data (unknown type code)` —— marshal 字节码是版本锁定的。
   解法：payload 改为携带**源码字符串**并用 `exec`/`eval` 执行，彻底不依赖 marshal，跨版本通用。

> 另外：`/api/user/update` 即使在无 cookie 时也返回 400（参数校验在鉴权之前），
> 所以它不能用来判断 token 是否有效；判断 admin 只能用 `/api/order/list` 的 403/200。

## 1. 漏洞根因

`POST /api/user/update` 把用户可控的 `key` 直接喂给 `pydash.set_(me, key, value)`：

```python
key = data.get("key"); value = data.get("value")
if "__builtins__" in key:                      # 唯一的防护：子串黑名单
    return jsonify({"ok": False, "msg": "字段路径非法: 该路径被禁止修改"}), 400
pydash.set_(me, key, value)                    # <-- 原型链/属性链污染
```

`pydash < 6.0.0` 没有 `RESTRICTED_KEYS`（该防护在 6.0.0 才引入：

```python
# pydash/helpers.py
RESTRICTED_KEYS = ("__globals__", "__builtins__")   # 6.0.0+ 才有
```

所以 `base_get()` 的 `getattr` 兜底会一路走 dunder 属性：

```
me.__init__            -> bound method
   .__globals__        -> app.py 的模块 globals（dict！）
       ["SECRET_KEY"]  -> 被覆盖
```

**关键点**：app.py 写的是 `from runtime_secrets import SECRET_KEY`，所以 `SECRET_KEY`
存在于 **app 模块自己的 globals** 里，而 `_secret()` 返回的正是这个模块全局变量：

```python
def _secret() -> str:
    return SECRET_KEY          # 读的是 app.py 模块全局
```

于是 JWT 的 HS256 签名密钥变成攻击者可控 → 可伪造 `role="admin"` 的 token。

题目描述"key 有点发紫"= 这个 key 能被"污染"（prototype pollution 梗）。
`rotate_flag` 从 `runtime_secrets` 导入，属于服务端未提供文件；它是一个线程，
作用域是"轮换 flag/密钥"，远程需要确认它是否会周期性重置 `SECRET_KEY`。

## 2. 利用链（三步）

1. `POST /api/register` + `POST /api/login` → 拿到普通 user 的 token（role=user）。
2. `POST /api/user/update`（带上面的普通 token）:
   ```json
   {"key": "__init__.__globals__.SECRET_KEY", "value": "<我选的任意字符串>"}
   ```
   响应会**用新密钥重新签发**一个 cookie；用 `<我选的字符串>` 验签即可确认污染成功。
   注意 handler 在 `set_` 之后把 `me.username/me.role` 恢复成原值，所以**污染
   `role` 没用**——必须污染模块级/全局状态。
3. 用该密钥自签 `{"username":..., "role":"admin", "iat":..., "exp":...}` → 
   `/api/order/list` 返回 200 证明已是 admin；
   `/api/order/buy` 的 `pickle.loads(base64.b64decode(cart))` 就是最终 sink（RCE）。

### 2.1 RCE 回显技巧（重要）

`api_order_buy` 先 `pickle.loads`，**之后**才检查 `isinstance(cart, list)`：

```python
except Exception as e:
    return jsonify({"ok": False, "msg": "购物车数据无法解析: %s" % e}), 400
```

所以只要 payload 在反序列化时抛异常，**异常消息会被回显在 JSON 里**。让 payload
执行命令并把输出塞进异常即可，无需反弹 shell / 回调监听：

```
raise KeyError(__import__('os').popen("<cmd>").read())
→ {"ok": false, "msg": "购物车数据无法解析: '<命令输出>'" }
```

### 2.2 pickle 载荷为什么手搓

`pickle.dumps` 的常规玩法都不满足"目标侧零依赖"：

- 自定义类 gadget → pickle 流里会写入 `__main__.MyClass`，目标 `__main__` 没有它；
- `os.popen(...)` 返回 `_wrap_close`，不是 list，虽已在异常前执行但回显不到；
- `compile()` 的返回值不可 pickle（`cannot pickle 'code' object`）；
- `functools.partial(eval, src)` 反序列化只是**重建** partial，不会调用它。

最终用纯 stdlib 手工拼字节码（`cbuiltins\neval\n` + `_codecs.encode` 绕过
protocol 0 无 bytes opcode 的限制）：

```
A = _codecs.encode(<marshal bytecode>, 'latin1')   # -> bytes
B = marshal.loads(A)                               # -> code object
R = builtins.eval(B)                               # -> 执行并 raise KeyError
```

踩过的坑（都已实测确认）：
- 可调用对象必须**先于** 参数的 `MARK` 入栈：`f ( t R`；
- py3 里 `eval` 不能写成 `ceval\n`（会被当成模块名 `eval`），要写 `cbuiltins\neval\n`；
- protocol 0 没有 bytes opcode，必须走 `_codecs.encode`。

## 3. 本地验证结果

用真实 pydash 5.1.2（从 PyPI 拉 wheel 解包到 `work/5_pollute/lib5.1.2`，未安装）
+ 桩 flask + **题目原版 app.py 的 handler 函数**：

- `verify_chain.py`：注册→登录→污染→伪造 admin→`/api/order/list` 200 → 全部 OK；
- `local_server.py`：把这些 handler 挂到 stdlib `ThreadingHTTPServer`，
  `scripts/5-solve.py` 打本机 5099 端口**完整跑通**，命令输出成功回显；
- `verify_primitive.py`：对照 pydash 5.1.2 / 6.0.2 / 7.0.7：
  5.1.2 污染成功；**6.0.2+ 报 `KeyError: access to restricted key '__globals__'`**。

### 3.1 试过但不通的路径（别重复踩）

| key | 结果 |
|---|---|
| `__init__.__globals__.SECRET_KEY` | ✅ 成功（主路径） |
| `__class__.__init__.__globals__.SECRET_KEY` | ✅ 成功（备用） |
| `__init__\.__globals__.SECRET_KEY` | ❌ 静默无效。pydash 只对**中间** token 反转义，最后一段没反转义 → 往 globals 写了个字面量 `"__globals__.SECRET_KEY"` 属性，HTTP 仍 200 |
| `__init__.__globals__.__dict__.SECRET_KEY` | ❌ 静默无效 |
| `__init__.__globals__.runtime_secrets.SECRET_KEY` | ❌ app 里没有 `runtime_secrets` 这个名字（是 `from ... import`） |
| `__init__.__globals__.sys.modules...` | ❌ app.py 没有 `import sys` |

## 4. 附件本身的问题（值得注意）

`app.py` 里 `USERS` 被大量引用（`USERS[username] = ...`、`USERS.get(...)`），
但**文件里从未定义 `USERS`**（只定义了 `USERS_LOCK` 和 `ORDERS`）。
照原样跑，`/api/register` 会直接 `NameError: name 'USERS' is not defined`。
判断是打包附件时漏了一行 `USERS = {}`（远程容器大概率是正常的，
否则 8 个队不可能解出）。本地验证时我在 harness 里补了 `appmod.USERS = {}`。

## 5. 待远程确认（拿不到容器，无法验证）

1. **pydash 版本**：启动横幅会打印 `Flask + pydash <ver>`。必须 < 6.0.0；
   若 ≥ 6.0.0，则 `__globals__`/`__builtins__` 被 pydash 自己挡掉，主路径失效——
   那需要换思路（题目描述"修修"可能暗示作者知道、并靠 app 层黑名单来"修"）。
2. **`rotate_flag` 行为**：是否周期性重置 `SECRET_KEY`。若是，污染与使用必须抢时间窗
   （脚本已实现"污染→立刻签发→立刻用"；失败会报 exit 6，重跑即可）。
3. **flag 落点**：`scripts/5-solve.py` 的默认命令会依次试 `env | grep -i flag`、
   `/flag`、`/flag.txt`、`/app/**`，最后 `grep -rIl '0xGame{' /`，覆盖面足够。
