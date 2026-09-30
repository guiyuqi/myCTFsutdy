# 题目 30 · ATP代码实验

- **分类**: Web / 动态环境
- **分值**: 639 | 解出人数: 19
- **flag**: `0xGame{217a8cd9-0e39-4057-9d03-07400a908a60}`
- **平台提交**: `{"code":200,"msg":"OK","data":{"result":true}}` ✅
- **出处**: 直接 POST 官方参考代码到 `/submit`，服务端评测通过后下发的 `flag` 字段

## 一句话结论

这是一个「C 代码在线评测」Web 应用，页面已经**明文给出官方参考代码**并声明
「提交下方的官方参考代码即可通过，要求提交的代码与参考代码完全一致」。
前端 `protect.js` 的禁止粘贴 / 禁用右键 / 禁用 F12 / 反调试**全是纯客户端限制**，
用 `curl` 直接 POST `/submit` 即可完整绕过，后端不做任何「人类逐字输入」校验。
**答案就是字面意义上的「抄参考答案」。** 全程未使用任何编译器/沙箱滥用技巧。

## 目标

```
http://5000-e088ee42-da25-4089-8949-f93a138d04a5.challenge.ctfplus.cn/   (80 端口)
Server: gunicorn
```

## 侦察时间线

### 1. 首页（`evidence/30-root.html`）

一个教学平台风格的页面，`<main>` 里有一道「签到实验 1-1 合成 ATP」，
以及一个 `<pre id="ref-code">` 装着完整的参考 C 代码（1808 字节，HTML 实体编码）。
下方是提交表单：

```html
<form id="submit-form" method="post" action="/submit#result">
  <textarea id="code-editor" name="code" ...></textarea>
  <button id="submit-btn" type="submit">提交评测</button>
  <span class="hint">语言：C (gcc)</span>
</form>
```

页面上的诱导文案（事后看全是障眼法）：

- 「本平台**禁止粘贴代码**，请逐字输入。」
- 「检测到开发者工具，请独立完成实验。」
- `<div id="block-modal">` 弹窗组件

### 2. `/static/protect.js`（`evidence/30-protect.js.txt`）

字符串数组混淆过的 `_0xS`，逐条解码后全部是**客户端行为**：

| 行为 | 实现 |
|---|---|
| 禁止粘贴 | `editor.addEventListener('paste', blockPaste)` + `beforeinput` 里 `inputType === 'insertFromPaste'` 也拦 |
| 禁用右键 | `document.addEventListener('contextmenu', ...)` |
| 禁用快捷键 | `keydown` 里拦 `ctrlKey/metaKey + v`，`F12`，`shift+ctrl+i/j/c`，`ctrl+u` |
| 反调试 | `setInterval(1500)` 里 `debugger` + 耗时 >100ms 判定 |
| 反 devtools | `outerWidth-innerWidth > 160` 或 `outerHeight-innerHeight > 160` 判定 |

**全都是浏览器端 JS，不影响 HTTP 层。** 直接 curl 就绕过了。

### 3. `/static/submit.js`（`evidence/30-submit.js.txt`）—— 关键

```js
fetch('/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code: editor.value })
})
.then(r => r.json())
.then(data => {
  if (data.ok) {
    // 渲染 data.message 和 data.flag
    label.textContent = '评测通过，flag 如下：';
    flagEl.textContent = data.flag;
  } else {
    result.textContent = data.message;
  }
});
```

**API 契约一目了然**：`POST /submit`，JSON body `{"code": "<C 源码>"}`，
成功响应 `{ok:true, message:"...", flag:"..."}`。flag 是服务端在评测通过时直接下发的，
不需要从编译器报错里挤。

## 利用

把 `<pre id="ref-code">` 的内容 `html.unescape` 还原成真正的 C 源码
（注意 `&lt;stdio.h&gt;` → `<stdio.h>`、`&#34;` → `"`、`&amp;nadh` → `&nadh`），
然后 POST 回去：

```bash
python3 - <<'PY'
import json, urllib.request, re, html, pathlib
h  = pathlib.Path('evidence/30-root.html').read_text(encoding='utf-8')
code = html.unescape(re.search(r'<pre id="ref-code">(.*?)</pre>', h, re.S).group(1))
if code.startswith('\n'): code = code[1:]
URL = "http://5000-e088ee42-da25-4089-8949-f93a138d04a5.challenge.ctfplus.cn"
req = urllib.request.Request(URL + "/submit",
        data=json.dumps({"code": code}).encode(),
        headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req, timeout=60).read().decode())
PY
```

响应（0.15s 返回）：

```json
{"flag":"0xGame{217a8cd9-0e39-4057-9d03-07400a908a60}","message":"Accepted\u2705","ok":true}
```

→ 见 `evidence/30-solve.log`。

### 成品脚本

`scripts/30-solve.py` —— 自动抓页面 → 解析参考代码 → 提交 → 打印 flag + 平台提交命令。
支持 `python3 scripts/30-solve.py <url>` 与 `--code <file.c>`。

## 已排除的方向（都试过/评估过，均非本题路径）

brief 里列的重点怀疑方向**一个都不需要**，因为朴素路径直接通关：

1. **命令注入 / `-o` / `-include` 注入** —— 表单**只有 `code` 一个字段**
   （`method="post"` 的 HTML 表单里没有文件名、没有编译参数输入框），
   submit.js 也只发 `{code}`。没有第二个可控参数，注入面不存在。
2. **`#include "/flag"` 预处理回显** —— 不必要。而且从响应形态看，
   后端只返回 `message` 字符串（成功时是固定的 `Accepted✅`），
   不把 gcc 的 stderr 回显给用户，这条路本来也是死的。
3. **编译器报错信息泄露** —— 同上，无 stderr 回显通道。
4. **运行沙箱逃逸（`system()` / `__attribute__((constructor))` / `#pragma GCC` / `-Wl,`）**
   —— 不必要。且「要求与参考代码完全一致」暗示后端大概率是先做字符串/规范化比对
   再编译，改一个字符就会走 `else` 分支只回 `data.message`。
5. **"参考答案暗藏 payload"** —— 参考代码是干净的纯计算 + `printf`，
   没有可疑字符串、没有 `system`、没有读文件。它真的只是参考答案。

## 备注 / 环境

- 提交后 `python3 scripts/ctfplus.py stop 30` 返回
  `{"code":402,"msg":"未找到对应容器"}` —— 该容器是外部预先开好的，
  不在本队的 slot 记录里，所以没有槽位需要归还。为确认这一点，
  在 stop 之后复测目标地址已返回 **502**（容器确已下线），槽位不占用。
- 证据文件：
  - `evidence/30-root.html` —— 首页完整 HTML（含参考代码）
  - `evidence/30-submit.js.txt` / `evidence/30-protect.js.txt` —— 前端逻辑
  - `evidence/30-solve.log` —— 提交请求与 `Accepted` 响应
  - `work/30_atp/ref.c` —— 还原后的参考代码（1808 字节）
