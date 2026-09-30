# 0xGame 2026 Writeup

> **赛事**：0xGame 2026（线上赛）
> **时间**：2026-09（Week1 起；赛后整理）
> **平台**：CTF+ 平台（`0xgame2026.play.ctfplus.cn`）
> **题目**：共 44 题，解出 39 题（88.6%）
> **flag 前缀**：`0xGame{...}`

---

## 1. 赛事概览

| 项 | 内容 |
|---|---|
| 赛事全称 | 0xGame 2026 |
| 主办 / 平台 | CTF+ 平台（`0xgame2026.play.ctfplus.cn`） |
| 比赛时间 | 2026-09（Week1 起；赛后整理） |
| 参赛形式 | 线上解题赛（动态容器题 + 离线附件题混合） |
| 题目总数 | 44 |
| 解出题数 | 39（88.6%） |
| 题目分类 | Web、Crypto、Pwn、Reverse、Misc、AI、Osint |
| flag 格式 | `0xGame{...}` |

本场 44 题覆盖七类，其中 **Pwn、Reverse、Misc、AI 四类全清**。最大瓶颈不是分析速度，而是平台**每队同时只允许 2 个动态容器**，所以动态题的排队顺序比并发度更关键。离线题大量依赖"手写解析器 + 交叉验证"：PDF、pcap、二维码、UPX 壳、pickle/pth 全部自写实现。非常规考点集中在四处：Unicode 运算符（17）、格式化串构造器缺陷（22）、pickle 反序列化的静态利用（41/43），以及作者自定义的 flag 清洗/输入语义（8、32）。5 道未解出题里，8 与 32 的密码学部分都已 100% 攻破，只差最后一层语义口径。

产物：45 份题解笔记、41 个可复现解题脚本、138 份证据文件。

## 2. 成绩统计

### 2.1 分类统计

| 分类 | 解出 / 总数 | 备注 |
|---|---|---|
| Web | 7 / 7 | **全清** |
| Crypto | 5 / 7 | 未解：8、32 |
| Pwn | 8 / 8 | **全清** |
| Reverse | 7 / 7 | **全清** |
| Misc | 8 / 9 | 未解：34（47 为 Misc+Web，计入 Misc） |
| AI | 4 / 4 | **全清** |
| Osint | 0 / 2 | 未解：14、23（23 为 5/6） |
| 合计 | 39 / 44 | 88.6% |

> 分类口径：按逐题索引中的分类标注逐题汇总（赛时记录的原始分类表与其逐题数据存在 1 题量级的算术差，本表按逐题数据重算）。

### 2.2 题目索引

| # | 题目 | 分类 | 分值 | 解出 | 状态 | flag |
|---|---|---|---|---|---|---|
| 1 | 错位的签名 | Web | 639 | 19 | ✅ | `0xGame{6ef4193d-672d-4d0b-b420-528761a926bc}` |
| 2 | 渲染如呼吸一样简单 | Web | 718 | 14 | ✅ | `0xGame{65ea3733-b722-4077-83d1-d5ea5703a535}` |
| 3 | 一切的开始 | Web | 833 | 8 | ✅ | `0xGame{f76f9b19-f808-4699-8020-763a0cc9441f}` |
| 4 | ez_64 | Web | 610 | 21 | ✅ | `0xGame{f021b158-6d33-4605-80a9-47edc0487729}` |
| 5 | pollute the key | Web | 833 | 8 | ✅ | `0xGame{a0205ff7-e61b-47f1-abad-a0ad75ff570f}` |
| 6 | 漏风的沙箱 | Web | 854 | 7 | ✅ | `0xGame{8c5ce232-0ffb-4ee7-8110-d06e43c9a79d}` |
| 7 | decode for love | Crypto | 900 | 5 | ✅ | `0xGame{ENCODINGGETTT}` |
| 8 | RSA永恒花园 | Crypto | 1000 | 1 | ❌ | — |
| 9 | 约会大作战 | Crypto | 973 | 2 | ✅ | `0xGame{Master_Origami}` |
| 11 | 为美好的密码献上解密 | Crypto | 1000 | 0 | ✅ | `0xGame{Offer the decryption for the beautiful password}` |
| 12 | 天使大人 | Crypto | 736 | 13 | ✅ | `0xGame{r34lly g00d st3p f0rw4ord}` |
| 14 | 至此,我将独自前行... | Osint | 1000 | 1 | ❌ | — |
| 15 | 奇妙杂货铺 | Pwn | 669 | 17 | ✅ | `0xGame{Welc0m3_7o_th3_pwn_w0rld!!!}` |
| 16 | 亦步亦趋 | Pwn | 854 | 7 | ✅ | `0xGame{R3t2t3xt_4nd_7th_st4ck_1s_m4gic}` |
| 17 | ！？数学基础？！ | Pwn(Scripting) | 812 | 9 | ✅ | `0xGame{Y0u_4r3_7h3_PY7h0n_m4st3r}` |
| 18 | 两次回响 | Pwn | 973 | 2 | ✅ | `0xGame{Sh3llc0de_c4n_do_3v3ry7h1ng}` |
| 19 | 保持沉默 | Pwn | 1000 | 1 | ✅ | `0xGame{W0W_y0u_kn0w_7h3_R372L1bc}` |
| 20 | 三扇门 | Pwn | 973 | 2 | ✅ | `0xGame{R3t2csu_wh4t_4_mag1c_func7i0n}` |
| 21 | 大道至简 | Pwn | 973 | 2 | ✅ | `0xGame{Sr0p_c4n_m4k3_y0ur_dream_c0m3_true}` |
| 22 | 这怎么可以作为名字啊！ | Pwn | 973 | 2 | ✅ | `0xGame{Kn0w_FMT_c4n_l3ak_m4ssag3}` |
| 23 | Spring的旅程-1 | Osint | 1000 | 1 | ❌ | — |
| 24 | 小伊卡...不胖...不胖... | Misc | 610 | 21 | ✅ | `0xGame{w0w_thi5_1s_thE_tru3_Length}` |
| 25 | 欢迎来到CTF的世界！ | Misc | 297 | 64 | ✅ | `0xGame{welcome_t0_the_w0rld_of_CTF!}` |
| 28 | [深具传统的ECC之诞生] | Crypto | 1000 | 1 | ✅ | `0xGame{master's touch}` |
| 29 | Strange_lsb | Misc | 792 | 10 | ✅ | `0xGame{LSB_x0r_Pl4n3_1s_4w3s0m3!}` |
| 30 | ATP代码实验 | Web | 639 | 19 | ✅ | `0xGame{217a8cd9-0e39-4057-9d03-07400a908a60}` |
| 32 | 四月是你的谎言 | Crypto | 1000 | 0 | ❌ | — |
| 33 | ez_traffic | Misc | 584 | 23 | ✅ | `0xGame{tr@ff1c_ana1y5is_i5_fUn_h77p!}` |
| 34 | 模糊二维码 | Misc | 1000 | 1 | ❌ | — |
| 35 | signin | Reverse | 494 | 31 | ✅ | `0xGame{0pen_1DA_4nd_start_y0ur_reverse_Engineering!}` |
| 36 | ez_upx | Reverse | 701 | 15 | ✅ | `0xGame{N0www_y0u_kn0w_UPX!!!}` |
| 37 | 欸？云朵 | Reverse | 754 | 12 | ✅ | `0xGame{Dyn4m1c_1$_s0_Fun!}` |
| 38 | 旧时代的信号 | Reverse | 792 | 10 | ✅ | `0xGame{JuS7_g1v3_16bit7t_@_try!!}` |
| 39 | z3_solver | Reverse | 773 | 11 | ✅ | `0xGame{z3_Se3ms_ezzz2z}` |
| 40 | Guess | Reverse | 812 | 9 | ✅ | `0xGame{Congratulations_0n_y0ur_v1ct0ry：）}` |
| 41 | ez_pytorch | AI | 773 | 11 | ✅ | `0xGame{3z_p1ckl3_fOr_pyt0rch}` |
| 42 | Treasure_island | Misc | 812 | 9 | ✅ | `0xGame{a5140046-2f49-4e34-8ca2-04f6c8663bbe}` |
| 43 | hd_pytorch? | AI | 973 | 2 | ✅ | `0xGame{37e4ae4a-2ee0-43c5-9d59-bb9b84530f8e}` |
| 44 | 粗心的小x | AI | 854 | 7 | ✅ | `0xGame{D0_n0t_uplO@d_pr1v4t3_th1ngs_t0_g1t}` |
| 45 | Magical Large Potato! | AI | 900 | 5 | ✅ | `0xGame{MLP_1s_s0_m4g1c}` |
| 46 | Interesting_ppt | Misc | 736 | 13 | ✅ | `0xGame{pptx_1s_just_a_z1p_4nd_metadata_n3ver_b3tr4ys_y0u}` |
| 47 | 奶蛙的博客 | Misc+Web | 610 | 21 | ✅ | `0xGame{n41w4_l4ugh5_cr4wl5_4nd_c0ll3ct5_3v3ry_fr4gm3nt_4cr055_th3_1nt3rn3t}` |
| 48 | 深夜值班室 | Misc | 833 | 8 | ✅ | `0xGame{56448caf-0fbc-41f8-82f4-21d36130a52e}` |
| 49 | ez_flower | Reverse | 833 | 8 | ✅ | `0xGame{WoW_Th3_f1ow3r$_@re_SOo0oo b3@u7ifull!!}` |

> 状态：`✅` 已解出 ｜ `⚠️` 部分解出 ｜ `❌` 未解出 ｜ `—` 不适用
> 题号沿用平台原始编号，10 / 13 / 26 / 27 / 31 为平台空缺编号，不存在对应题目。

## 3. 逐题 Writeup

> 每题统一结构：**元信息 → 思路 → 关键步骤 → 关键代码 → 踩坑 → 产出**。
> 元信息四行固定：`分类` / `状态` / `flag` / `附件`。
> `关键代码` 只在题目存在决定性片段时给出（本场多数题目没有），未出现即表示无。

### 3.1 · 错位的签名

- **分类**：Web
- **状态**：✅ 已解出 ｜ 639 分 ｜ 19 解
- **flag**：`0xGame{6ef4193d-672d-4d0b-b420-528761a926bc}`
- **附件**：—（动态环境）

**思路**

网关 APISIX 的 `jwt-auth` 插件存在**算法混淆**（CVE-2026-39999，CVSS 9.8）：验签密钥取自 Consumer 配置的 RS256 `public_key`，而**签名算法取自攻击者可控的 JWT header `alg`**。把公开可取的 admin 公钥 PEM 当作 HMAC-SHA256 密钥自签一个 token，即可伪造管理员身份。

**关键步骤**

1. 指纹：`Server: APISIX/3.16.0`。
2. 未鉴权的 `GET /public-key` 直接返回 admin 公钥 PEM。
3. 已排除 CVE-2020-13945 / CVE-2022-24112（Admin API 未挂载）。
4. 构造 header `{"alg":"HS256","role":"admin"}`，用**去掉末尾换行的 PEM 原文**作 HMAC-SHA256 密钥签名。
5. 携带该 token 访问 `GET /flag`。

**踩坑**

- HMAC 密钥必须与配置里 `public_key` 字符串**逐字节相同**——命中变体是**去掉末尾换行的 PEM**，带换行的版本签名无效。

**产出**：`scripts/1-solve.py`、`notes/1-错位的签名.md`

---

### 3.2 · 渲染如呼吸一样简单

- **分类**：Web
- **状态**：✅ 已解出 ｜ 718 分 ｜ 14 解
- **flag**：`0xGame{65ea3733-b722-4077-83d1-d5ea5703a535}`
- **附件**：—（动态环境）

**思路**

首页自曝 `engine: jinja2-preview`，`POST /render` 的 `template` 参数**直接进入 `render_template_string()`**，构成 Jinja2 SSTI → RCE。flag 不在文件系统里，而在容器环境变量 `FLAG`。

**关键步骤**

1. 引擎指纹：`{{7*7}}`=49 且 `{{7*'7'}}`=7777777 ⇒ Jinja2（Twig 在这两个测试下都会是 49）。
2. 用 `curl`/`playwright` 打 payload `{{ cycler.__init__.__globals__.os.popen('id').read() }}` 打通 RCE。
3. 读容器 env `FLAG` 取 flag。

**踩坑**

- 先做引擎指纹，一步排除 PHP 系与 Twig，省掉一轮无用尝试。
- `/flag` 是 `root:0400` 读不到，但 `entrypoint.sh` 写明 flag 由 env 写入——**读不到文件不等于没 flag**。

**产出**：`scripts/2-solve.py`、`notes/2-渲染如呼吸一样简单.md`

---

### 3.3 · 一切的开始

- **分类**：Web
- **状态**：✅ 已解出 ｜ 833 分 ｜ 8 解
- **flag**：`0xGame{f76f9b19-f808-4699-8020-763a0cc9441f}`
- **附件**：—（动态环境）

**思路**

`robots.txt` 泄露隐藏入口 `Disallow: /inex233`，入口后面是一台**五层传参链**校验器：每一层必须同时满足上一层的全部条件，缺一个就回退。

**关键步骤**

1. `robots.txt` → `Disallow: /inex233`。
2. GET 参数 `aaa=flag`。
3. POST form 参数 `bbb=flag`。
4. 需 `Cookie: sweet=sweet`。
5. 需 `Referer: http://127.0.0.1/`。
6. 需 JSON body `{"bbb":"flag","web":"flag"}` → flag。

**踩坑**

- 第 6 步**只认 `Referer`**——`X-Forwarded-For` / `X-Real-IP` / `Client-IP` / `Forwarded` 全部无效。
- `Host: 127.0.0.1` 会被前置网关拦成"域名未备案"。
- 第 7 步切 JSON 后 `bbb` 必须一并放进 JSON body。

**产出**：`scripts/3-solve.py`、`notes/3-一切的开始.md`

---

### 3.4 · ez_64

- **分类**：Web
- **状态**：✅ 已解出 ｜ 610 分 ｜ 21 解
- **flag**：`0xGame{f021b158-6d33-4605-80a9-47edc0487729}`
- **附件**：—（动态环境）

**思路**

无参访问即 `highlight_file(__FILE__)` 泄露源码：字符白名单 `preg_match("#^[/?. fla64]*$#",$c)` 之后**直接 `system($c)`**。"64" 指 base64，而白名单只允许 `/ ? . 空格 f l a 6 4`，于是用 **shell 通配符**拼出要执行的命令。

**关键步骤**

1. 无参访问拿到源码，确认白名单与 `system()` 调用。
2. 构造 `c=/???/???/?a??64 ????????` → 展开为 `/usr/bin/base64 flag.php`。
3. 解 base64 输出得 flag。

**踩坑**

- `system()` 只回显 stdout，`stderr` 不可见——**空响应 ≠ 文件不存在**，不要因为一次空白输出就换方向。

**产出**：`scripts/4-solve.py`、`notes/4-ez_64.md`

---

### 3.5 · pollute the key

- **分类**：Web
- **状态**：✅ 已解出 ｜ 833 分 ｜ 8 解
- **flag**：`0xGame{a0205ff7-e61b-47f1-abad-a0ad75ff570f}`
- **附件**：`app.py`

**思路**

`POST /api/user/update` 把用户可控 key 直接丢给 `pydash.set_()`，唯一防护是子串黑名单 `if "__builtins__" in key`。**pydash < 6.0.0 没有 `RESTRICTED_KEYS`**（6.0.0 才引入），`base_get` 的 `getattr` 兜底可以走 dunder 链改到模块全局。

**关键步骤**

1. 用 `requests` 提交 key `__init__.__globals__.SECRET_KEY` → 覆盖 app 模块全局。
2. JWT HS256 密钥随之可控 → 伪造 `role=admin`。
3. `/api/order/buy` 的 `pickle.loads(cart)` 是 RCE sink；用 `KeyError(os.popen(cmd).read())` 从异常回显命令输出。
4. handler 在 `set_` 后会恢复 `username/role`，且 `rotate_flag` 会秒回滚 `SECRET_KEY` ⇒ 需**后台持续污染 + 循环撞窗口**（实测 100/100 命中）。

**踩坑**

- ① handler 在 `set_` 后会恢复 `username/role`，**污染 role 无效，必须污染模块全局**。
- ② `rotate_flag` 会**秒回滚 SECRET_KEY**（响应里重签的 cookie 验签通过、下个请求就不认）→ 需后台持续污染 + 循环撞窗口（实测 100/100）。
- ③ worker 是 **Python 3.10.21**，`marshal.dumps(compile(...))` 报 `bad marshal data` → 改为携带**源码字符串**的 gadget。

**产出**：`scripts/5-solve.py`、`notes/5-pollute-the-key.md`

---

### 3.6 · 漏风的沙箱

- **分类**：Web
- **状态**：✅ 已解出 ｜ 854 分 ｜ 7 解
- **flag**：`0xGame{8c5ce232-0ffb-4ee7-8110-d06e43c9a79d}`
- **附件**：`app.py`

**思路**

`POST /run` 的沙箱由「NFKC → 46 条正则黑名单（只查源码文本）→ ASTFilter → `exec(code, {'__builtins__': dict(builtins.__dict__)})`」组成，**三处防护同时漏**，于是照常拿到全量内建并读文件。

**关键步骤**

1. ① `print.__self__` 就是 builtins 模块（`__self__` 未进黑名单）→ 取 `__dict__` 拿全量内建。
2. ② 名字拼接 `'op'+'en'` 让源码正则失明，且拼接结果是 BinOp，绕过只拦 `ast.Constant` 的 `visit_Subscript`。
3. ③ `.read` 被封 → **迭代文件对象** `for _l in f:`。
4. payload：`for _l in print.__self__.__dict__['op'+'en']('/flag'): print(_l)`；flag 实际在 **env `FLAG`** 与 `/app/flag.txt`。

**踩坑**

- 三条绕过必须同时成立：`__self__` 逃出 builtins 限制、`'op'+'en'` 拼接同时让源码正则失明并绕过 AST 常量检查、用迭代文件对象替代被封的 `.read`。

**产出**：`scripts/6-solve.py`、`notes/6-漏风的沙箱.md`

---

### 3.7 · decode for love

- **分类**：Crypto
- **状态**：✅ 已解出 ｜ 900 分 ｜ 5 解（离线）
- **flag**：`0xGame{ENCODINGGETTT}`
- **附件**：`week1 Crypto decode for love.txt`

**思路**

附件是 4 层编码叠加：**emoji-aes 表情表逆映射（rotation=0）** → CryptoJS **AES-256-CBC**（passphrase = 题面给的 `0x2026`）→ Base64 → **凯撒位移 7**。用 `cryptography` 复现解密链即可。

**关键步骤**

1. emoji 表情表逆映射（rotation=0）还原出 CryptoJS `Salted__` 密文。
2. AES-256-CBC 解密，passphrase 就是题面字符串 `0x2026`。
3. Base64 解码。
4. 凯撒位移 7 还原 flag。

**踩坑**

- 这题**不是** 2009 贴吧原帖那套摩斯 / T9 / 栅栏——**必须以附件实际内容为准**，不要照抄网上的老题解。
- 判据用"只有 rotation=0 能解出 `Salted__` 头与合法 PKCS7"，而不是靠肉眼判断表情表对齐。

**产出**：`scripts/7-solve.py`、`notes/7-decode_for_love.md`

---

### 3.8 · RSA永恒花园

- **分类**：Crypto
- **状态**：❌ 未解出 ｜ 1000 分 ｜ 1 解
- **flag**：—
- **附件**：`week1 Crypto RSA永恒花园 .py`

**已确证的事实**

- 题面 n 为 154 位（= 3 × 507-bit 素数，**非法模数**：两枚 `getPrime(256)` 之积至少 510 bit），hint1 要求 155 位。
- 穷举全部 1550 个"插入一位数字"候选后按"两枚 256-bit 素数之积必为奇数且无小因子"过滤得 170 个，再查 FactorDB：**只有末尾补 `7` 的那个完全分解**，且恰为两个 256-bit 素数：
  - `n_full = 10941738641570527421809707322040357612003732945449205990913842131476349984288934784717997257891267332497625752899781833797076537244027146743531593354333897`（155 位）
  - `p = 102639592829741105772054196573991675900716567808038066803341933521790711307779`（256 bit）
  - `q = 106603488380168454820927220360012878679207958575989291522270608237193062808643`（256 bit）
- 解密结果唯一：`e = 65537`、`d = e⁻¹ mod (p−1)(q−1)`，明文 **50 字节** = `ff001337` + `0xGame{%you_￥have@keen#eyes&for*Crypto!}` + `80007fee`（`￥` 是 U+FFE5，UTF-8 = `ef bf a5`），并已回代校验 `m^e mod n_full == c`。
- 花括号内 6 个杂质字符 `% ￥ @ # & *` 位于明文索引 **7 / 12 / 17 / 22 / 27 / 31**，正好各自落在 6 个单词之前。

**卡点**

- "杂质是插入还是替换"**无法从数据本身区分**。若纯插入，唯一还原是 `you_havekeeneyesforCrypto!`（已被平台拒绝）⇒ 必为替换，而被替换的原字符只能靠语义推断，两种自然语义（下划线 / 空格）**均被拒**。共试 6 个候选（平台提交 5 次）全灭，返回一律 `{"code":402,"msg":"flag错误"}`：`0xGame{you_have_keen_eyes_for_Crypto!}`、`0xGame{%you_￥have@keen#eyes&for*Crypto!}`、`0xGame{you_havekeeneyesforCrypto!}`、`0xGame{you have keen eyes for Crypto!}`、`0xGame{_you__have_keen_eyes_for_Crypto!}`。
- ⇒ "淤泥"这个词的真实所指尚未破解：它可能不是指那 6 个字符，而是指两段哨兵 `ff001337` / `80007fee` 或它们编码的规则。**需官方 hint 或直接问作者。**

**后续方向**

- 平台该题 hint 当时是空串，等官方补 hint；作者「不得其名」（同出 7/9/11/12/28/32），一句话即可定死清洗规则。
- 已排除、不必重做：直接对题面 n 解密、`gcd(n1,n2)` 共用素因子（全工作区再无第二个 ≥50 位整数）、Fermat（1550 个候选各 200k 轮，覆盖 |p−q| ≤ 2^138）、Wiener / 小私钥、≤1e5 试除、12 个素数模数候选、`m + k·n`（k ≤ 40）、附件隐藏数据（616 B，无零宽字符、无附加流）、公开 WP（全网检索无此题解）。
- 在拿到新信息前**不要再盲试变体**（平台限速 10 次/分钟）。

**产出**：`scripts/8-solve.py`（含 `--search` 复现 FactorDB 搜索）、`notes/8-RSA永恒花园.md`

---

### 3.9 · 约会大作战

- **分类**：Crypto
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{Master_Origami}`
- **附件**：—（动态环境）

**思路**

服务用的是自定义 DH：`p` 虽是 378-bit 素数，但 **`p−1` 光滑**；真正可利用的后门不是 `A=g^a`（`g` 的阶是 257bit 大素数），而是响应里给出的 12 个小阶元素 `B[12]`——对小阶元素穷举即可还原私钥的各个模数分量，再用 CRT 组合。

**关键步骤**

1. 用 `pwntools` 连服务、`sympy` 分解：`p-1 = 2 · (1019…1091 共 12 个小素数) · q_big(257bit)`。
2. 确认数组 `B[12]` 的阶逐个等于那 12 个小素数。
3. 每项满足 `H[i] = sha256(最小 big-endian 字节串(B[i]^a mod p))`：枚举 `k∈[0,q_i)` 比对哈希，得 `a mod q_i`。
4. CRT 组合还原私钥 `a`。
5. 顺着 3 轮选项（C, A, C）拿 flag。

**踩坑**

- 哈希口径是 **`sha256(最小 big-endian 字节串)`**，不是 hex、也不是十进制字符串——口径错则一个都撞不上。
- 不要对 `A=g^a` 直接 Pohlig–Hellman（`g` 的阶是 257bit 大素数），**必须走 `B[i]` 小阶元素**这条后门。

**产出**：`scripts/9-solve.py`、`notes/9-约会大作战.md`

---

### 3.11 · 为美好的密码献上解密

- **分类**：Crypto
- **状态**：✅ 已解出 ｜ 1000 分 ｜ 0 解
- **flag**：`0xGame{Offer the decryption for the beautiful password}`
- **附件**：—（动态环境）

**思路**

交互式 ECDSA（NIST521p + sha512），参数**跨连接固定**。hint 说 `k` 由 **length-5 LFSR** 生成 ⇒ `k` 的轨道周期恰为 31，因此取 32 条签名必然包含同一 `k` 的一对，解线性方程即可恢复私钥。

**关键步骤**

1. 实测 `rs[i]==rs[i+31]` 在 29/29 组上成立 ⇒ 确认周期为 31。
2. 取 32 条签名，找出同 `k` 的一对，用 `k=(h_i-h_j)/(s_i-s_j)`、`d=(s_i·k-h_i)/r` 恢复私钥 `d`。
3. 最后阶段 `r` 固定为 `x(G)`（即 `k∈{1,n-1}`，服务用的是 `k=n-1`）。
4. 用 `pwntools` + `sympy` + `cryptography` 完成签名与阶段交互。

**踩坑**

- ① `h = sha512(打印出来的 ASCII hex 字符串)`，**不是 raw 16 字节**。
- ② `s` 是 `int(input())`，**必须发十进制**——发 hex 会让它抛异常回 `bye`（极易误判成"越界"）。
- ③ 请求数须 ≥32 才进下一阶段。

**产出**：`scripts/11-solve.py`、`notes/11-为美好的密码献上解密.md`

---

### 3.12 · 天使大人

- **分类**：Crypto
- **状态**：✅ 已解出 ｜ 736 分 ｜ 13 解
- **flag**：`0xGame{r34lly g00d st3p f0rw4ord}`
- **附件**：`关于邻家的天使大人不知不觉把我惯成废人这档子事.py`

**思路**

附件脚本在数域 `Q(θ)` 上定义 4 个数学量，环境无 Sage，于是用 `sympy` **等价翻译**原脚本、复现出 4 个量，再把摘要交回 nc 服务换取 flag。核心陷阱是**数域的特征是 0，不能沿用同文件里 `GF(2^8)` 的化简习惯**。

**关键步骤**

1. 读附件，抄出 4 个数学量的定义。
2. 用 `sympy` 等价复现（不做 Sage 专有运算），得到字符串 `88|2645|1149364915685671|9846`。
3. 计算 `sha256("88|2645|1149364915685671|9846")`。
4. 把该 hex **上传到 nc 服务**换取 flag。

**踩坑**

- ★ 数域 `Q(θ)` 是**特征 0**，**不能沿用同文件里 `GF(2^8)` 的特征 2 化简习惯**：正确是 `θ⁸=2θ²+3θ+2` ⇒ `u=12+4θ+5θ²` ⇒ **norm=2645**（误按特征 2 会得 1487）。
- 当时对范数做了"三重交叉校验"且三法一致——**但三种方法校验的是同一个写错输入**：**多方法只能验算，不能验建模**。

**产出**：`scripts/12-solve.py`、`notes/12-天使大人.md`

---

### 3.14 · 至此,我将独自前行...

- **分类**：Osint
- **状态**：❌ 未解出 ｜ 1000 分 ｜ 1 解
- **flag**：—
- **附件**：—（题面内嵌配图 `小狼公主.webp`）

**已确证的事实**

- 「小狼公主」= **A-SOUL 珈乐 / Carol**：题目示例的假 BV `BVQ2Fyb2w520` 中 `Q2Fyb2w` = base64("Carol")；2022-05-10 = 官方宣布珈乐「直播休眠」（粉丝语境里的"离开"）。
- 歌词「你像窝在被子里的舒服，却又像风捉摸不住」出自**蔡健雅《红色高跟鞋》**（非周杰伦 / 温岚）。
- 承载线索的视频 = `BV1db4y117Q1`（珈乐本人账号《红色高跟鞋》翻唱，owner 珈乐Carol / mid 351609538，`pubdate 2021-09-17 17:00:00`，`ctime 2021-09-14 20:45:50`）：1080p 逐帧确证左下角手写歌词**只有半句**——t≈35–40s `你像窝在被子里的舒服`、t≈42–48s 角落**空白**、t≈52–54s `红色高跟鞋`。
- 该视频有**隐藏第二 P**，标题字面 `A.S.F.03019`（cid 408134980，24s，逐帧无文字）；分 P **无独立 pubdate**（`view` / `player/pagelist` / `player/v2` / `view/detail` 全试过，只有两页共用的 ctime 与主 pubdate）。
- 1080p 取流方法（可复用）：`/x/player/playurl?...&qn=80&fnval=1&fnver=0&fourk=1&platform=html5&high_quality=1` 返回 `quality: 80`（1920×1080）且**无需登录**，同一视频用 `platform=pc` 只给 360P。

**卡点**

- 「线索字符串」与「线索指向的秘密视频」两段始终未定死。**9 次提交全部返回 `{"code":402,"msg":"flag错误"}`，且全部以 `BV1db4y117Q1` 打头** ⇒ 强烈提示第 1 段应为另一支视频。最后 1 次改用该视频简介里**全站独有的符号串** `（ ▂▃▅ ██▓▓▓ █ ┗┛◥▲Ψ▂▃█ ▅ ）` 仍被拒。
- 格式口径已回源核对排除：平台题目原文示例为 `0xGame{BVQ2Fyb2w520_love&hope_2026-09-28-9:00:00}`，即**月 / 日补零、时不补零**，此前提交用的 `2021-09-17-17:00:00` 与示例同构，不是格式问题。
- 团队 10 次提交全灭。

**后续方向**

- 珈乐 2022-03-02 录播（`BV1zP4y1c7Hu` 29:03）原话「**自己去红色高跟鞋下面链接**」——暗示该视频简介 / 下方挂过链接，「秘密视频」可能由此指向。**建议优先排查简介里的链接 / BV 号。**
- 尚未逐帧核对的残余候选：`BV1Fq4y137wb`(1252s)、`BV1bB4y1M736`(274s)、`BV1wg411G7bm`(267s) 的中段。
- 三段候选（BV × 线索串 × 发布时间）已按置信度列在 `notes/14-至此我将独自前行.md`；`BV1t3411s7mh`（把 `03019` 读成 2022-03-19，"珈乐想要说出的话"那天）与 `BV1H341127zr`（全站唯一标题含 `A.S.F.03019` 的视频）是中等置信度的替代路线。

**产出**：`notes/14-至此我将独自前行.md`、`work/14_osint/`（722 份录播 SRT 全文库 + 逐帧 / 取流脚本）

---

### 3.15 · 奇妙杂货铺

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 669 分 ｜ 17 解
- **flag**：`0xGame{Welc0m3_7o_th3_pwn_w0rld!!!}`
- **附件**：—（动态环境）

**思路**

结算逻辑 `cost = price * number; balance -= cost` 对购买数量**没有正数校验**，负数量即可让总价变负、余额反向增加——这是一道整数符号校验缺失题。

**关键步骤**

1. 用 `pwntools` 连服务，选择购买接口。
2. 买 `-10000` 瓶 → `cost = -100000` → 余额从 100 变成 100100。
3. 再买标价 99999 的 Flag。

**踩坑**

- 本题无额外坑点（整数下溢即唯一考点），一次提交通过。

**产出**：`scripts/15-solve.py`、`notes/15-奇妙杂货铺.md`

---

### 3.16 · 亦步亦趋

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 854 分 ｜ 7 解
- **flag**：`0xGame{R3t2t3xt_4nd_7th_st4ck_1s_m4gic}`
- **附件**：`pwn`

**思路**

两关 ret2text：Level1 的 `read` 固定长度恰好能从 `buf` 覆盖到相邻的局部变量 `magic`；Level2 用 `gets()` 溢出返回地址，而程序自己 `printf` 泄漏了 `win` 地址（PIE 由此绕过）。用 `fw-decompile` + `pwntools` 完成。

**关键步骤**

1. Level1：`buf[0x20]@rbp-0x20`、`magic@rbp-0x4` → 偏移 **28**，`read(0,buf,0x20)` 恰好覆盖 `magic`。
2. Level2：`gets()` 无长度限制，偏移 **40**，程序自己 `printf` 泄漏 `win` 地址（PIE）。
3. 栈对齐：`leave;ret` 之后 `rsp%16==0`，而 ABI 要求函数入口 `rsp%16==8`，在跳进 `win` 前垫一个 `ret`（即 `win+0x28`）。
4. 用 `gdb` 取证栈 / 寄存器快照，确认对齐与偏移。

**踩坑**

- ★ **栈 16 字节对齐**——`leave;ret` 后 `rsp%16==0` 而 ABI 要求入口 `rsp%16==8`，直接 `ret` 进 `win` 会因 glibc `do_system` 的 `movaps` 崩（SIGSEGV −11）；**前面垫一个 `ret`（`win+0x28`）**即可。

**产出**：`scripts/16-solve.py`、`notes/16-亦步亦趋.md`

---

### 3.17 · ！？数学基础？！

- **分类**：Pwn（Scripting）
- **状态**：✅ 已解出 ｜ 812 分 ｜ 9 解
- **flag**：`0xGame{Y0u_4r3_7h3_PY7h0n_m4st3r}`
- **附件**：—（动态环境）

**思路**

服务连答 100 道四则运算即给 flag（不吐 shell），唯一的难点是**运算符是 Unicode 而非 ASCII**，其中减法用的是汉字「一」，任何 ASCII 正则都会翻车。

**关键步骤**

1. 用 `pwntools` 连服务，循环读取算式。
2. 手工映射运算符（100 轮实测只有 4 种）：`＋`=U+FF0B→`+`、**`一`=U+4E00（汉字"一"）→`-`**、`x`=U+0078→`*`、`÷`=U+00F7→`/`。
3. 100 轮全程 4.5–5.5 秒，答完即得 flag。

**踩坑**

- ★ **运算符是 Unicode 而非 ASCII**（实测 100 轮只有 4 种）：`＋`=U+FF0B→`+`、`一`=U+4E00（汉字"一"）→`-`、`x`=U+0078→`*`、`÷`=U+00F7→`/`。
- `NFKC` 能折全角 `＋`，但**汉字 `一` 不会被折成 `-`，必须手工映射**——用 `[0-9+\-*/]` 正则必翻车。

**产出**：`scripts/17-solve.py`、`notes/17-数学基础.md`

---

### 3.18 · 两次回响

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{Sh3llc0de_c4n_do_3v3ry7h1ng}`
- **附件**：`pwn`

**思路**

程序 `mmap(NULL,0x1000,RWX)` + `read(0,buf,9)` + `call rdx`，只给 **9 字节 shellcode 预算**；用两阶段读把预算拆成"发起第二次读"和"落回 `execve`"，第二次读就地覆盖自己。

**关键步骤**

1. stage-1 = `31c031ff6a7f5a0f05`（`xor eax,eax; xor edi,edi; push 0x7f; pop rdx; syscall`）发起第二次 read。
2. 必须显式设 `rdx`（0x7f），否则其初值是 buf 地址，`read` 会 `-EFAULT`。
3. stage-2 在第 9~10 字节放 `eb 00`（`jmp +0`）跳过填充，落到 `execve("/bin//sh",0,0)`。
4. 用 `gdb` 复核寄存器与 `jmp rsi` 的执行流，确认第二次写入的偏移。

**关键代码**

```asm
; stage-1：9 字节，只负责发起第二次 read 覆盖自身
31 c0        xor eax, eax
31 ff        xor edi, edi
6a 7f        push 0x7f
5a           pop rdx
0f 05        syscall

; stage-2：第 9~10 字节放 eb 00 (jmp +0) 跳过填充，落到 execve("/bin//sh",0,0)
```

**踩坑**

- ① 第二次 read 写回 buf 会覆盖正在执行的 `jmp rsi` → SIGILL（必须靠 `jmp +0` 把执行流引到自己可控的偏移上）。
- ② 不设 `rdx` 会因原值是 buf 地址而 `-EFAULT`。

**产出**：`scripts/18-solve.py`、`notes/18-两次回响.md`

---

### 3.19 · 保持沉默

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 1000 分 ｜ 1 解
- **flag**：`0xGame{W0W_y0u_kn0w_7h3_R372L1bc}`
- **附件**：`pwn`

**思路**

题面的"两个密钥"其实是 `put()` 里的两个**立即数** `0xdeadbeef` / `0x9527`；"死寂"来自全局 `flag` 计数器**初值为 1**，只有第一次 `vuln()` 会 `close(1)`。重进 `main()`（此时计数为 0）后 stdout 不再被关，两个阶段就能干净地串成一条 ret2libc 链。

**关键步骤**

1. 呈递两个立即数 `0xdeadbeef` / `0x9527` 后，`put()` 执行 `dup2(2,1)` 把 stdout 接回。
2. 全局 `flag` 计数初值 1 ⇒ 只有第一次 `vuln()` 会 `close(1)`；重进 `main()` 后 stdout 保留。
3. 用 `pwntools` + 本地下载的同版本 libc 构造 ret2libc：`system=0x50d70`、`binsh=0x1d8678`。
4. 全流程用 `gdb` 与本地 fd 日志验证（`19-local-fd0.log` 等）。

**踩坑**

- ① 凭记忆写的 libc 偏移 `system=0x50d60` 是**错的**（正确 `0x50d70`，`binsh=0x1d8678`）。
- ② 泄露**不能按行读**（libc 地址低位可能是 `0x0a`），要 `recvn` 定长。
- ③ pwntools `recvuntil(timeout=)` 超时会**静默返回部分数据**。

**产出**：`scripts/19-solve.py`、`notes/19-保持沉默.md`

---

### 3.20 · 三扇门

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{R3t2csu_wh4t_4_mag1c_func7i0n}`
- **附件**：`attachment.zip`

**思路**

`win(a,b,c)` 要求 `a==0x111 && b==0x222 && c==0x333`，而程序只给了 `pop rdi;ret`、**没有 pop rsi/rdx**，于是用 `__libc_csu_init` 的 **ret2csu** 万能 gadget 布置三个参数（题目 Welcome 点名的"破门工具"）。

**关键步骤**

1. 用 `fw-decompile` 反编译定位 `__libc_csu_init` 的两个 gadget。
2. 关键点：`call [r15+rbx*8]` 是**对 `r15` 解引用**，所以 `r15` 必须指向**存放函数指针的内存**（如 `system@got`）。
3. 旁证：正常启动时 `__libc_csu_init` 用的 `r15` 是 `.init_array` 地址。
4. glibc 2.31 的 `system()` 走 posix_spawn 路径有 `movaps`，要求 `rsp≡8 (mod 16)`，需要垫 `ret`。
5. 脚本里同时实现了三条链：SYSTEM / CSU / CSU_WIN。

**踩坑**

- ★ **`call [r15+rbx*8]` 是对 `r15` 解引用**——把 `r15` 直接设成 `win` 地址会变成 `call [win]`（把代码字节当函数指针）→ SIGSEGV；`r15` 必须指向**存放函数指针的内存**（如 `system@got`）。
- ② glibc 2.31 `system()` 在 posix_spawn 路径有 `movaps`，要求 `rsp≡8 (mod 16)`，需垫 `ret`。

**产出**：`scripts/20-solve.py`（三条链 SYSTEM / CSU / CSU_WIN）、`notes/20-三扇门.md`

---

### 3.21 · 大道至简

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{Sr0p_c4n_m4k3_y0ur_dream_c0m3_true}`
- **附件**：`pwn`

**思路**

极简 **SROP**：`.text` 仅 125 字节、4 个函数全是裸 syscall；`vuln` 溢出 0x18 到 RIP 且返回前 `xor rax,rax`，而 `magic` 里 `write` 返回 15 **顺手把 `rax` 刷成 15**——正好是 `rt_sigreturn` 的系统调用号。

**关键步骤**

1. 用 `pwntools` 分析：`vuln` 溢出偏移 0x18 到 RIP。
2. 走 `magic` 分支让 `write` 返回 15，落进 `rax`。
3. 用 `syscall;ret` gadget 触发 `rt_sigreturn`，SROP frame 里用 `.data` 段的 `/bin/sh`。

**踩坑**

- `read(0,buf,0x400)` 会吞掉紧跟 payload 发出的 shell 命令 → 发完 payload 要 `sleep ~0.3s` 再交互。

**产出**：`scripts/21-solve.py`、`notes/21-大道至简.md`

---

### 3.22 · 这怎么可以作为名字啊！

- **分类**：Pwn
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{Kn0w_FMT_c4n_l3ak_m4ssag3}`
- **附件**：`attachment.zip`

**思路**

把"名字"**直接当 printf 格式化串**用两次：第 1 次既泄漏 libc 基址、本身又恰好是合法 shell 命令；第 2 次把 `puts@got` 改写成 `system`，于是 `puts(buf)` 变成 `system("sh;#…")`。

**关键步骤**

1. 第 1 次 payload `sh;#%23$p|%8$s\0\0` + `p64(printf@got)`：既泄漏 libc 基址，本身又是合法 shell 命令（`#` 之后全被注释成 `sh`）。
2. 第 2 次把 `puts@got` 写成 `system`。
3. 因 pwntools 的 `fmtstr_payload` 不可靠，改为自写 `build_fmtstr()`：只用 `%hn`、按块值升序发射、地址 8 字节对齐追加兼作 NUL 终止。
4. 用 C harness 做本地对照测试（`evidence/22-fmtstr-bugtest.txt`）。

**关键代码**

```python
# 第 1 次：泄漏 libc 基址，同时自身就是合法 shell 命令
b"sh;#%23$p|%8$s\0\0" + p64(printf_got)

# 第 2 次：puts@got -> system（自写构造器，只用 %hn，按块值升序发射）
build_fmtstr(offset, {puts_got: system_addr})
```

**踩坑**

- ★ **pwntools `fmtstr_payload(offset,{...},write_size='short')` 会生成错误 payload**——混用 `%lln/%hhn/%n` 时后一条 4 字节写会覆盖前一条的高位（C harness 实测 6 个测试值里 2 个写错，`puts@got` 变成 `0x844a50d70` → SIGSEGV）。必须改为自写 `build_fmtstr()`。
- ② pwntools 的 `libc.address` 会跨重试残留，重试前要重置。

**产出**：`scripts/22-solve.py`、`notes/22-这怎么可以作为名字啊！.md`

---

### 3.23 · Spring的旅程-1

- **分类**：Osint
- **状态**：❌ 未解出（容器内 6 小题**已过 5**）｜ 1000 分 ｜ 1 解
- **flag**：—
- **附件**：`picture.zip`（`eat.jpg`、`night.jpg`）

**已确证的事实**

- 容器是 Flask 6 题、逐题校验、判分严格；**答题进度是会话级的**（存在 session cookie 里），实例过期 / 重启即清零，但 5 个已通过的答案可秒级重填（`work/23_spring/solve23.py`）。
- q1 `江苏省_南京市`（照片发布者 = 博客 springbot.top 博主 Spring，About me 写明「南京邮电大学(NJUPT)」，0xGame 即南邮新星赛）。
- q2 `https://www.springbot.top/nctf-2026-wp/`（该帖内嵌 night 原图 `IMG_20260406_195915`，配文「比赛结束出去拍的一张图，有人猜到这是哪里吗？」）。
- q3 `HUAWEI/nova 14`（EXIF Make/Model）。
- q4 `2026年04月06日19:22:45`（EXIF `DateTimeOriginal`）。
- q6 **`0sint_master?`**：挑战附件 `night.jpg` 末尾比博客原图**多出 20 字节 Base64** `MHNpbnRfbWFzdGVyPw==`。

**卡点**

- q5 问的是「night 照片里建筑的高德 POI 全名」，已排除约 **210 个候选串**（各高架地铁站名及 4 种格式变体、主要商场与景区地标，全量记录见 `work/23_spring/q5_attempts.txt`）。
- 视觉特征：2–3 层商业裙房，下层玻璃店面（暖光内透）→ 米色石材腰线 → 二层整层玻璃幕墙 → 顶部**通长成对"折扇 / 摊开书页"式白色弧形挑檐**（深色钢柱 + 不锈钢 S 形曲臂 + 板下线灯）；左前方**爬满爬山虎的混凝土箱梁 + 梁顶玻璃栏板（可上人）**；街面有白底绿叶涂装公交、「即停即走」禁停牌、缠灯串大树、金色麦穗 / 星芒 LED。幕墙上的"金红烟花"是反射。
- 卡住的原因：需要**以图搜图**，但四个引擎均被挡——Bing 的 `imgurl=` 退化为文本搜索、Yandex 弹 SmartCaptcha、百度识图 `Reject`、`lens.google.com` 本机不通（**未尝试绕过验证码**）。**需要人类用自带浏览器识图，或直接认出该建筑。**

**后续方向**

- 最强图案证据是 **南京万达茂（仙林）系**：南京唯一以「金陵折扇」为主题外立面的建筑（"梅开五福，扇展春风"），与"成对白色弧形折扇挑檐"同源，且紧邻 NJUPT 仙林。待试字符串：`仙林万达茂广场`、`南京仙林万达茂广场`、`万达茂(南京仙林)`、`万达茂商业广场`、`南京万达茂商业广场`、`南京仙林万达茂购物中心`。
- 次选：溧水万达广场（紧邻 S7 轻轨高架站，老城区 + 区属公交 + 亮化）。
- 以图搜图推荐上传图（已裁好）：`work/23_spring/pics/rs_1_facade.jpg`（首选）、`rs_2_full.jpg`、`rs_3_bridge.jpg`；也可直接用公开直链 `https://www.springbot.top/wp-content/uploads/2026/04/IMG_20260406_195915-scaled.jpg`。
- **不要再盲试**容器候选；拿到图像检索结果后再小批量验证。

**产出**：`notes/23-Spring的旅程-1.md`（含"接手必读"）、`work/23_spring/solve23.py`（会话级秒级重填 5 题）

---

### 3.24 · 小伊卡...不胖...不胖...

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 610 分 ｜ 21 解（离线）
- **flag**：`0xGame{w0w_thi5_1s_thE_tru3_Length}`
- **附件**：`little1kA.zip`

**思路**

PNG 的 **IHDR 高度字段被手改**（改成 1280），但**像素数据没动**；用 IHDR CRC 校验失败定位字段被改，再用 IDAT 解压后的真实字节数反推原始尺寸。

**关键步骤**

1. 用标准库 `zlib` 解析 PNG，校验 IHDR CRC：存储 `0xb757db33` / 计算 `0xd2ab0767` ⇒ 失败。
2. IDAT 解压后按 `6751500 ÷ (1500×3+1) = 1500` 反推真实尺寸 **1500×1500**。
3. 改回 IHDR 高度、重算 CRC32 → 图上直接可读 flag。

**踩坑**

- 第一次把 `thi5` 的数字 **5** 误读成字母 **s**（低分辨率下极像）；用连通域字高判定（x-height 39px vs 数字 53px）才敢定案。题目名里的 `Length` 是双关。
- 第 2 次提交才成功——第一次是因为把 `5` 读成 `s` 而失败。

**产出**：`scripts/24-solve.py`、`notes/24-小伊卡.md`

---

### 3.25 · 欢迎来到CTF的世界！

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 297 分 ｜ 64 解（离线）
- **flag**：`0xGame{welcome_t0_the_w0rld_of_CTF!}`
- **附件**：`CTF入门指北.pdf`

**思路**

PDF 正文里直接写了「这里有串神秘字符送给你：`MHhHYW1le3dlbGNvbWVfdDBfdGhlX3cwcmxkX29mX0NURiF9`」，Base64 解码即 flag。真正的考点是环境里**没有任何 PDF 工具**且禁止 `pip install`，必须自写提取器，且中文子集 CID 字体必须走 `/ToUnicode` CMap。

**关键步骤**

1. 自写 PDF 文本提取器：解析 `N 0 obj` 对象表 + 22 个 `/ObjStm` 对象流。
2. 定位 `/Type/Page` 的 `/Resources/Font` 与 `/Contents`。
3. 用各字体的 `/ToUnicode` CMap 解 `Tf/Tj/TJ` 的十六进制串。
4. 取到 Base64 串后解码得 flag。

**踩坑**

- 环境**无任何 PDF 工具**且禁止 `pip install` ⇒ 只能自写通用提取器（解析 `N 0 obj` 表 + 22 个 `/ObjStm` 对象流 → `/Type/Page` 的 `/Resources/Font`/`/Contents` → 用各字体 `/ToUnicode` CMap 解 `Tf/Tj/TJ` 十六进制串）。
- **中文子集 CID 字体必须走 CMap，否则全是乱码。**

**产出**：`scripts/25-solve.py`（**可直接复用于其他 PDF 题**）

---

### 3.28 · [深具传统的ECC之诞生]

- **分类**：Crypto
- **状态**：✅ 已解出 ｜ 1000 分 ｜ 1 解
- **flag**：`0xGame{master's touch}`
- **附件**：—（动态环境）

**思路**

服务**完全非交互**（连上即打印参数并断开，参数跨连接固定）。曲线 `y² = x³ + 3x`、`p ≡ 3 (mod 4)` ⇒ **超奇异，迹 t=0 ⇒ `#E(F_p) = p+1`**；而 `p+1` **完全光滑**（最大素因子仅 29 bit），于是 Pohlig–Hellman + BSGS 直接解出私钥。

**关键步骤**

1. 用 `sympy` + `pycryptodome` 与自写 EC 运算解析 banner 参数。
2. 验证 `p ≡ 3 (mod 4)` 与迹 t=0 ⇒ 群阶为 `p+1`。
3. 分解 `p+1`，确认最大素因子仅 29 bit。
4. Pohlig–Hellman + BSGS 解出 `d`；提交前本地验证 `d·G == Q`。

**踩坑**

- 预设的「ECDSA nonce 重用 / 无效曲线 / 范围校验」三类方向**全部不适用**——服务根本没有签名 `(r,s)`，不要在这上面浪费时间。
- 提交前本地验证 `d·G == Q` 才发，一次命中。

**产出**：`scripts/28-solve.py`、`notes/28-ECC之诞生.md`

---

### 3.29 · Strange_lsb

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 792 分 ｜ 10 解（离线）
- **flag**：`0xGame{LSB_x0r_Pl4n3_1s_4w3s0m3!}`
- **附件**：`week1-misc-strange_lsb.zip`

**思路**

提示「唯有**三原色交织**之时」= **三通道 LSB 逐位异或** `(R&1)^(G&1)^(B&1)`；得到的 1bpp 位图正中央是一枚完整 QR 码。

**关键步骤**

1. 用 `PIL` + `numpy` 取三通道 LSB 做逐位异或。
2. 该位图置位比例仅 **0.1393**（随机应为 0.5），是全图唯一的统计异常。
3. 渲染后正中央是完整 **QR 码**（version 4、33×33、EC level H、mask 2、反色）。
4. 环境无 `zbar`/`zxing`/`cv2`，用**自写 QR 解码器**读出内容（finder 校验 + format BCH + 去掩码 + 之字形取码 + 反交织）。

**踩坑**

- ★ 图片是 JPEG 转存的夜空照，三通道本质是同一张灰度图，**逐通道看 LSB 是完全均匀的噪声**（1 比例 0.4999、自相关 0.001）⇒ 我们据此把 8 个位平面 × 6 通道序 × 512 组 `R:a,G:b,B:c` × 旋转 / 翻转 / 蛇形 / 分块 × 派生色彩空间 × 文件级隐写**全部跑穷**仍无果。
- **判据错了**：单通道 LSB 随机 ≠ 无载荷，**必须检查跨通道 LSB 的联合分布**（三元组直方图一眼可见 XOR=0 的 4 种各约 0.215、XOR=1 的各约 0.035）。

**产出**：`scripts/29-solve.py`、`evidence/29-xor-lsb-plane.png`（肉眼可见 QR）

---

### 3.30 · ATP代码实验

- **分类**：Web
- **状态**：✅ 已解出 ｜ 639 分 ｜ 19 解
- **flag**：`0xGame{217a8cd9-0e39-4057-9d03-07400a908a60}`
- **附件**：—（动态环境）

**思路**

首页 `<pre id="ref-code">` 里明文放着「官方参考代码」，页面自己写着"提交下方的官方参考代码即可通过"；`/static/submit.js` 又泄露了接口契约 `POST /submit {"code": "..."}`，因此不需要任何注入。

**关键步骤**

1. `curl` 取首页，抠出 `<pre id="ref-code">` 的内容。
2. 做 **HTML 反转义**。
3. `POST /submit {"code": "..."}` → 0.15s 返回 flag。

**踩坑**

- `/static/protect.js` 的禁粘贴 / 禁右键 / 禁 F12 / 反调试**全是纯客户端 JS**，对 HTTP 层零影响。
- 表单只有 `code` 一个字段，**注入面根本不存在**——预设的命令注入 / `#include` / 报错回显 / 沙箱逃逸全部是死路。

**产出**：`scripts/30-solve.py`、`notes/30-ATP代码实验.md`

---

### 3.32 · 四月是你的谎言

- **分类**：Crypto
- **状态**：❌ 未解出 ｜ 1000 分 ｜ 0 解
- **flag**：—
- **附件**：—（动态环境）

**已确证的事实**

- 服务参数跨连接固定（连 3 次比对完全一致），banner 给出 `message = YOU DID LIVE IN MY HEART` 与 `hash(key+message) = 46af62962126aa38e4f1680a6c64bc6b`（32 位 hex ⇒ MD5）。
- **密钥 = `bytes.fromhex("2026")` = `b" &"`**（作者把题面的 `0x2026` 当**字节对 `20 26`** 用，不是字面 6 字符串），且穷举证明唯一：全 1 字节（256）无解、全 3 字节（2^24）无解、全 2 字节（65536）唯一解 `b" &"`；本地断言 `md5(b" &" + b"YOU DID LIVE IN MY HEART").hexdigest() == 46af62962126aa38e4f1680a6c64bc6b` 成立。
- 发送非 ASCII 字节（如 `\x80\n`）会拿到未捕获异常的完整回溯：`/app/challenge.py:40` 的 `if compare_digest(submitted_hash, expected_hash)`，`main()` 在 47 行被调用（全文仅 47 行）。这说明 `submitted_hash` 是**由输入直接构造的 str**——若是 hex 摘要则恒为 ASCII，永远不会触发该 TypeError。

**卡点**

- 服务要求「echo the mission in `hash(key+message+response)`」，但**从不给出 `expected_hash`**，且对任何 ASCII 输入都回同一句 `not matter,moon and sun have their next April`（长度 0/1/5/16/31/32/63/64/100 全部实测无差异；把各种摘要本身、含原始 16 字节二进制摘要回填也无差异，无时序差、无二次输入）。
- 已排除：**MD5 length extension**（完整实现并自测通过、klen 0..64 全枚举，`work/32_lie/md5le.py`，回复不变——因为构造是 `md5(key‖message‖response)`，response 在后，且服务不给目标摘要，无法闭环）、密钥文本（`md5(b"0x2026"+MSG)` 不命中）、`TOO`、banner 摘要本身、`compare_digest` 类型混淆使其恒真（str 对 bytes 直接 `TypeError`）。
- 已提交 `0xGame{ &}` 与 `0xGame{TOO}` 各一次，均 `{"code":402,"msg":"flag错误"}`。

**后续方向**

- 从**未捕获异常的回溯**继续榨源码（已成功触发一次并看到 `/app/challenge.py:40`）：换错误类型可能看到更多行或变量值——比继续猜 `response` 更有希望。
- 向作者 / 官方 hint 索要 `expected_hash` 的口径，或确认「response 后面加 TOO」到底加在哪一侧、是否要带引号 / 空格。
- **在没有可复现依据前不要再提交**（第 8 题正是死在这一点上）。

**产出**：`scripts/32-solve.py`、`work/32_lie/md5le.py`（可复用 length extension）

---

### 3.33 · ez_traffic

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 584 分 ｜ 23 解（离线）
- **flag**：`0xGame{tr@ff1c_ana1y5is_i5_fUn_h77p!}`
- **附件**：`ez_traffic.zip`

**思路**

附件是 pcap，环境无 `tshark`/`scapy`/`tcpdump`，因此**手写 pcap 解析器**按四元组重组 TCP 流，从 HTTP 响应体里取出一个未加密压缩的 zip。

**关键步骤**

1. 手写解析器：Ethernet→IPv4→TCP→按四元组重组。
2. 295 包 = 15 条流，其中 14 条是诱饵；真载荷是 `GET /download/secret.zip`。
3. 该响应体 172B 就是完整 zip（**未加密 deflate**），解压得 base64 → flag。

**踩坑**

- 9001 端口的自制 `TELEMETRY/1.0` 协议写着 `payload-is-not-http`，是**诱饵**，不要在这里浪费时间。
- 手切 zip 时易漏 `local header` 30B 之后的 10B 文件名偏移。

**产出**：`scripts/33-solve.py`、`notes/33-ez_traffic.md`

---

### 3.34 · 模糊二维码

- **分类**：Misc
- **状态**：❌ 未解出 ｜ 1000 分 ｜ 1 解（离线）
- **flag**：—
- **附件**：`QRcoooold.zip`（`QRcoooold/messyQR.jpg`，1280×1707 JPEG）

**已确证的事实**

- 图是一张**拼豆（perler/hama beads）实物照片**：板面四角 TL(114.5,639.3) TR(1084.8,610.7) BR(1090.8,1535.9) BL(190.8,1596.2)，板宽顶部 ~946 px / 底部 ~905 px；peg 间距（干净区自相关 r≈0.92）17.97 / 18.27 / 18.35 px ⇒ 板面横向 ≈ **50–51 个 peg**。
- 珠子 **614 颗全部严格插在 peg 上**（逐点采样 51×51 = 2601 个格位；珠距 ≡ peg 间距 18.0px，相位无歧义率 0.921），密度仅 **23.6%**（真 QR 需 45–55%）。板面矫正后的珠阵与照片逐珠对照一致，提取本身没有问题。
- **finder pattern 全图穷举 0 命中**（横 + 纵两个方向 × 8 档阈值 100/110/128/140/160/175/190/210 × 模糊核 5/7/9/11 × 模块 6–100px × 容差 0.45–0.60）。
- 结构评分穷举（版本 1–9 × 全部偏移 × 正反色 × 8 种二面体朝向 × 旋转 0–45° × 非整数模块尺寸）最高 **0.64 / 0.69**（随机 ≈0.50，真 QR ≈0.95）；无 timing pattern（最长交替游程只有 8）；正反色 / 8 种二面体 / 45° 棋盘子格 / 非整数模块 / 站立珠-平躺珠拆分 / JPEG 位平面 / ICC / 尾部数据全部干净。
- ZXing 3.5.3（MultiFormatReader、TRY_HARDER）对整图 / 板面裁切 / **每 10° 旋转共 72 张变体**全部 `NotFoundException`。
- 结论是**否定性**的：这张图里不存在可识别的二维码，也就没有"版本 / 纠错等级 / 掩码"可以反解。

**卡点**

- 题面唯一钥匙是被打码的 **【**】** =「某位**拖稿画家**的**笔名**」（工具 / 概念名）。检索到最可能是 **[Merricx/qrazybox](https://github.com/Merricx/qrazybox)（QR Code Analysis and Recovery Toolkit）**——正是"手动重建 format info + 按 QR 机制补 RS 纠错"的工具，与题面完全对应——但**未能建立"拖稿画家的笔名"→工具名的联想**，因此不知道作者期望用哪种"非位置"的方式把二维码读出来。

**后续方向**

- 题面说「**还没拼完**就不小心弄乱了」，所以**低密度是合理的**——关键是缺失部分要靠 format info + RS 纠错反推（正是 QRazyBox 的主业）。**若日后想到【**】，这就是入手点。**
- 珠子**全部在 peg 上**说明不是物理打翻造成的错位，"弄乱"很可能是出题人算法生成的一种（可逆？）变换——与直觉相反，值得下一位注意。
- `QRcoooold` 可能是「QR is cool」的谐音（搜到过同名的 QR 纠错演示站），也可能只是"冷 / 未熨烫的拼豆"的梗。

**产出**：`scripts/34-solve.py`

---

### 3.35 · signin

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 494 分 ｜ 31 解（离线）
- **flag**：`0xGame{0pen_1DA_4nd_start_y0ur_reverse_Engineering!}`
- **附件**：`signin.zip`

**思路**

MinGW-w64 编译的 PE32+ x86-64：`main` 要求 `strlen==0x34`，`check_input@0x401550` 把 `input[i] XOR 0x5A` 与 VA `0x4040a0` 的 52 字节表逐字节比较，反向异或即得 flag。

**关键步骤**

1. 用 `objdump` 反汇编，定位 `check_input@0x401550` 与 52 字节常量表 `0x4040a0`。
2. 对该表逐字节 XOR `0x5A` 得 flag（明文也直接存在于 `.rdata@0x404060`，两条路径互相印证）。
3. 校验长度 `0x34`。

**踩坑**

- 本题无特别坑点（明文同时躺在 `.rdata`，两条路径互证），一次提交通过。

**产出**：`scripts/35-solve.py`、`notes/35-signin.md`

---

### 3.36 · ez_upx

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 701 分 ｜ 15 解（离线）
- **flag**：`0xGame{N0www_y0u_kn0w_UPX!!!}`
- **附件**：`attachment1.zip`

**思路**

UPX 5.02 + LZMA 加壳的 PE32+。环境**没有 `upx`**，于是用 **Unicorn 直接执行壳 stub** 脱壳，拿到原始映像后再逆校验逻辑。

**关键步骤**

1. 用 Unicorn 把 3 个节映射到 `0x400000`。
2. 伪造并 hook 5 个导入函数。
3. 从 EP `0x40d960` 执行到 **OEP `0x401cc0`**（共 2,291,008 条指令），dump 出原始镜像。
4. 校验逻辑：循环异或 key=`vivo50` → base64 → 与常量 `strcmp` ⇒ 反推 flag。

**踩坑**

- 环境无 `upx`，只能靠 Unicorn 逐指令执行到 OEP（229 万条指令）；映射节、伪造 5 个导入缺一不可，否则 stub 中途就崩。

**产出**：`scripts/36-solve.py`、`notes/36-ez_upx.md`

---

### 3.37 · 欸？云朵

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 754 分 ｜ 12 解（离线）
- **flag**：`0xGame{Dyn4m1c_1$_s0_Fun!}`
- **附件**：`attachment2.zip`

**思路**

PE32+ x64 GUI 程序，"闪过去的东西"是**字面意思**：窗口类名就叫 `CloudFlashWindow`，`WM_PAINT` 分支里把一段 26 字节用 RC4 解密后 `DrawTextA`，紧接着 `DestroyWindow` —— flag 只存在一帧。

**关键步骤**

1. 从窗口类名 `CloudFlashWindow` 与 `WM_PAINT` 分支（`0x401871`）定位绘制逻辑。
2. `.rdata@0x405050` 的 26 字节用 **RC4** 解密，密钥 `ShedaLight`（**以明文躺在 `.rdata@0x405038`**）。
3. 解密结果交给 `DrawTextA` 绘制。
4. 用 Unicorn 执行 PE 内真实机器码，并与独立的 Python RC4 实现交叉验证（逐字节一致）。

**踩坑**

- 本机无 wine，无法真跑 `.exe`；改用 **Unicorn 执行 PE 内真实机器码**与独立 Python RC4 交叉验证（逐字节一致）。

**产出**：`scripts/37-solve.py`（`--emulate` 自带交叉验证）、`notes/37-云朵.md`

---

### 3.38 · 旧时代的信号

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 792 分 ｜ 10 解（离线）
- **flag**：`0xGame{JuS7_g1v3_16bit7t_@_try!!}`
- **附件**：`attachment3.zip`

**思路**

附件只有 **192 字节的 MS-DOS MZ 16 位实模式**程序（所以双击会提示"此应用无法运行"）；核心是一个 33 轮的自定义流加密循环。

**关键步骤**

1. 读 MZ 头：header size=2 段=0x20 ⇒ 载入镜像 = 文件去掉 0x20 头。
2. 镜像偏移 `0x12` 起是一个 33 轮循环：`p[i] = (ror(c[i],3) - 7 - i) ^ k`，密钥流 `k_next = rol(k + p[i], 1) ^ i`，初值 `0xa7`。
3. 解出后程序走 DOS `int 21h AH=09` 打印 `"Signal recovered: "` + 明文。
4. 用 `unicorn` + `objdump` 执行验证（`emu_start` 的 `begin` 是相对 CS 基址的偏移；必须给 `SS:SP` 映射内存）。

**踩坑**

- unicorn `emu_start` 的 `begin` 是**相对 CS 基址的偏移**而非线性地址。
- 必须给 `SS:SP` 映射内存，否则第一条 `push cs` 就 `UC_ERR_WRITE_UNMAPPED`。

**产出**：`scripts/38-solve.py`、`notes/38-旧时代的信号.md`

---

### 3.39 · z3_solver

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 773 分 ｜ 11 解（离线）
- **flag**：`0xGame{z3_Se3ms_ezzz2z}`
- **附件**：`attachment4.zip`

**思路**

`main` 要求 `strlen==0x17`（23），唯一校验 `FUN_00401550` 是一组**环状线性方程**，边界 `x[i]∈0x20..0x7e` 恰好把解钉死；直接建模丢给 `z3` 即可 sat。

**关键步骤**

1. 用 `fw-decompile` 反编译 `FUN_00401550`，得到方程：`3·x[i] + 5·x[(i+1)%23] + 11·x[(i+7)%23] + 7·x[(i+4)%23] == C[i]`，`x[i]∈0x20..0x7e`。
2. z3 用 `BitVec8` + `ZeroExt(16)` 建模求解。
3. 回代 23/23 条方程全等（脚本自带 `assert`）。
4. 常量表按 PE 节表现场读取，不硬编码。

**踩坑**

- 本题无特别坑点；回代 23/23 条方程的断言即完整性证明，一次提交通过。

**产出**：`scripts/39-solve.py`（常量表按 PE 节表现场读取，不硬编码）

---

### 3.40 · Guess

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 812 分 ｜ 9 解（离线）
- **flag**：`0xGame{Congratulations_0n_y0ur_v1ct0ry：）}`
- **附件**：`attachment5.zip`（内含 `attachment.exe`）

**思路**

`attachment.exe` 是 **PyInstaller onefile**（Python 3.14）。手工解析 CArchive 取出其中的裸 marshal 流，用标准库 `marshal`/`dis` 还原逻辑——猜数字纯属幌子（猜中只打印假 flag），真 flag 由硬编码常量经 **XTEA 解密**得到。

**关键步骤**

1. 手工解析 CArchive（魔数 `MEI\x0c\x0b\x0a\x0b\x0e` + big-endian TOC），无需 pyinstxtractor 即可取出 `game` 条目。
2. 该条目是**无 pyc 头的裸 marshal 流**，本机 Python 3.14 直接 `marshal.loads` + `dis`。
3. 真 flag = 硬编码常量经 **XTEA 解密**（`DELTA=0x9E3779B9`、32 轮、`KEY=b'guess_secret_key'`）后 PKCS#7 去填充。
4. 程序自带 `secret.startswith(b'0xGame{')` 校验，可作免费的完整性证明。

**踩坑**

- flag 结尾是**全角标点** `：` `）`，提交时不能写成半角。
- 算法**从不打印**结果，但程序自带 `secret.startswith(b'0xGame{')` 校验 ⇒ 是免费的完整性证明，无需 angr。

**产出**：`scripts/40-solve.py`

---

### 3.41 · ez_pytorch

- **分类**：AI
- **状态**：✅ 已解出 ｜ 773 分 ｜ 11 解（离线）
- **flag**：`0xGame{3z_p1ckl3_fOr_pyt0rch}`
- **附件**：`attach.zip`

**思路**

`.pth` 是 torch 新版 zip 容器，`model/data.pkl` 里是一个 `GLOBAL '__builtin__ exec'` + `BINUNICODE`（恶意源码）+ `REDUCE` 的 pickle——这正是 `weights_only=True` 报错的原因。我们用 `pickletools.genops` **静态**抠出源码，绝不执行。

**关键步骤**

1. 用 `zipfile` 打开 `.pth`，取出 `model/data.pkl`。
2. 用 `pickletools.genops` 从 `BINUNICODE` 操作数中**安全抠出**恶意源码。
3. 手写重实现源码里的 4 段解码：循环 XOR / 反转 + base64 / hex 后 `(b[i]-i)&0xFF` / base64 后首字节 XOR 链。

**踩坑**

- **绝对不要直接 `torch.load()` / `pickle.load()`** 这个文件。

**产出**：`scripts/41-solve.py`、`notes/41-ez_pytorch.md`

---

### 3.42 · Treasure_island

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 812 分 ｜ 9 解
- **flag**：`0xGame{a5140046-2f49-4e34-8ca2-04f6c8663bbe}`
- **附件**：—（SSH 靶机 `player@<target>`）

**思路**

SSH 登录后先用"数一数图上有什么"定位隐藏箱子（`real_map.txt` 的行数），再通过 player **可写目录** unlink 掉 root 守护链的心跳脚本，让 watchdog 主动放开 `/tmp/flag` 的权限。

**关键步骤**

1. SSH 登录（`player` / `0xGame2026`；环境无 `sshpass`，改用 `paramiko`）。
2. `clue.txt` 写「Count what the chart keeps」→ `real_map.txt` 恰好 **611 行** ⇒ 箱子是 **`box_611`**（其余 999 个都是 `Empty...`）。
3. 箱内指路 `/tmp/flag`（`---------- root:root`，由 root 守护链 `/etc/.flagd/{entrypoint,respawn,watchdog}.sh` + `runuser -u player /opt/.whisper/heartbeat.sh` 封印）。
4. **突破口**：`/opt/.whisper/heartbeat.sh` 及其目录都是 **`player:player` 可写** ⇒ player 有 unlink 权。
5. `rm -f` 掉它 + `kill -9` 心跳进程（**只做一半会被 `respawn.sh` 重新拉起**）⇒ watchdog 把 `/tmp/flag` 放开权限，读 flag。

**踩坑**

- 删脚本与杀进程必须**同时完成**：只做一半会被 `respawn.sh` 重新拉起，前功尽弃。

**产出**：`scripts/42-solve.py`、`notes/42-Treasure_island.md`

---

### 3.43 · hd_pytorch?

- **分类**：AI
- **状态**：✅ 已解出 ｜ 973 分 ｜ 2 解
- **flag**：`0xGame{37e4ae4a-2ee0-43c5-9d59-bb9b84530f8e}`
- **附件**：—（`POST /upload`）

**思路**

`POST /upload`（multipart，字段 `file`，限 2MB）之后服务端 `torch.load()`，是 pickle 反序列化；服务端只加了一层 **pickle 字节流关键字黑名单**，用 `builtins.eval` 即可绕过。

**关键步骤**

1. 必须是 **zip 容器格式**的 `.pth`（裸 pickle 会报 `Invalid magic number`）→ 手工用 `zipfile` 拼 `archive/data.pkl` + `archive/version`。
2. 探测黑名单：字节流含 `os`/`system`/`popen`/`subprocess` 即 403。
3. 绕过 = **`builtins.eval`**：`(eval, ("open('/flag').read()",))` —— 字节流里不含任何被拦词，响应直接回显 flag。

**踩坑**

- 服务端还会打印「已降级为兼容模式加载」，等于主动关掉 `weights_only` 防护——这句话本身就是可利用点的确认。

**产出**：`scripts/43-solve.py`、`notes/43-hd_pytorch.md`

---

### 3.44 · 粗心的小x

- **分类**：AI
- **状态**：✅ 已解出 ｜ 854 分 ｜ 7 解（离线）
- **flag**：`0xGame{D0_n0t_uplO@d_pr1v4t3_th1ngs_t0_g1t}`
- **附件**：`AI-chat-project.zip`（含 `chat_export.json`）

**思路**

`AI-chat-project.zip` 内嵌**完整 `.git/`**，而 `.gitignore` 只忽略 `__pycache__/*.pyc/.venv/`（**没忽略 `.env`**）；3 个 "API KEY" 都是 `sk-` + base64(`partN:<片段>`)，三段缺一不可，正好对应"当前文件 / git 历史 / 未忽略的 `.env`"三个位置。

**关键步骤**

1. git 历史：`git log -p --all` 在 commit `79edd41` 里找被 refactor 删掉的硬编码 key（part2）。
2. 工作区：part1 在 `chat_export.json`。
3. 未忽略文件：part3 在 `.env`。
4. 三段拼接后 base64 解码；第 4 个 key 是诱饵（base64 → `This_is_a_fake_key`）。

**踩坑**

- `sk-` 后紧跟的 4 个字符是盐（解出明文前 3 字节是垃圾，应按"含 `part`"定位而不是按偏移猜）。
- 第 3 段把 `+` 写成了 `@`，需要还原后再解码。

**产出**：`scripts/44-solve.py`、`notes/44-粗心的小x.md`

---

### 3.45 · Magical Large Potato!

- **分类**：AI
- **状态**：✅ 已解出 ｜ 900 分 ｜ 5 解（离线）
- **flag**：`0xGame{MLP_1s_s0_m4g1c}`
- **附件**：`Magic_Large_Potato.zip`

**思路**

`.pth` 是 `torch.save` 的 zip 容器、内容是无混淆的 `state_dict`。`embedding.weight` 形状 `(23,32)`，后面接 MLP `32→128→256→128→100`，**最后一层输出 100 恰好 = `len(string.printable)`** ⇒ 这是个字符分类器：把 23 行 embedding 送进 MLP 取 argmax 就是 flag 的 23 个字符。

**关键步骤**

1. 环境无 `torch` ⇒ 用 `pickle.Unpickler` 子类 + `persistent_load` 回放 `FloatStorage`。
2. 按 pickle 里的 `(offset,size,stride)` 用 `as_strided` 还原张量。
3. 纯 `numpy` 完成 MLP 推理。
4. 对 23 行 embedding 逐行取 argmax，拼出 flag。

**踩坑**

- 环境无 `torch`，必须自己回放 `FloatStorage` 并正确处理 `(offset,size,stride)` 布局，否则张量形状对不上。

**产出**：`scripts/45-solve.py`、`notes/45-Magical_Large_Potato.md`

---

### 3.46 · Interesting_ppt

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 736 分 ｜ 13 解（离线）
- **flag**：`0xGame{pptx_1s_just_a_z1p_4nd_metadata_n3ver_b3tr4ys_y0u}`
- **附件**：`0xgame.zip`

**思路**

pptx 本质是 zip，信息藏在两处 `docProps` XML 元数据里：`core.xml` 的修订号字段后藏一段裸 base64（提供 XOR 密钥），`custom.xml` 里被删值的水印属性仍残留 base64 密文。

**关键步骤**

1. 用标准库 `zipfile` 打开，读 `docProps/core.xml`：`</cp:revision>` 后藏**裸 base64** `a2V5PTB4R2FtZV8yMDI2` → `key=0xGame_2026`。
2. 读 `docProps/custom.xml`：`AIGC` 水印属性被删了 `<vt:lpwstr>` 值，但**残留 base64 密文**。
3. base64 解码 → **重复密钥 XOR**（key=`0xGame_2026`）→ 再 base64 解码 → flag。

**踩坑**

- 本题无特别坑点（`zipfile` + `base64` 直读 XML 即可），一次提交通过。

**产出**：`scripts/46-solve.py`、`notes/46-Interesting_ppt.md`

---

### 3.47 · 奶蛙的博客

- **分类**：Misc+Web
- **状态**：✅ 已解出 ｜ 610 分 ｜ 21 解
- **flag**：`0xGame{n41w4_l4ugh5_cr4wl5_4nd_c0ll3ct5_3v3ry_fr4gm3nt_4cr055_th3_1nt3rn3t}`
- **附件**：—（动态环境）

**思路**

提示「美丽的汤」= BeautifulSoup（写爬虫），而**提示直接写在响应头 `X-Hint`**：`fragments are gzip -> base64 -> split; join in page order`。每页里有**两个**碎片 span，可见的才是真碎片，`display:none` 的是等长干扰项。

**关键步骤**

1. 读响应头 `X-Hint` 拿到拼接规则（gzip → base64 → 按页序拼接）。
2. 首页说明共 124 篇，逐篇请求 `/page?id=N`。
3. 每页取可见的 `.flag-fragment`，忽略 `display:none` 的 `.frag`（等长干扰项）。
4. 按页序拼出 124 字符 base64 → gunzip → flag。（环境无 `bs4`，用标准库 `re` + `html` 等效实现。）

**踩坑**

- 碎片含 `+ / =` 且以 **HTML 实体**形式出现，必须先 `html.unescape`，否则 base64 解不开。

**产出**：`scripts/47-solve.py`、`notes/47-奶蛙的博客.md`

---

### 3.48 · 深夜值班室

- **分类**：Misc
- **状态**：✅ 已解出 ｜ 833 分 ｜ 8 解（Minecraft 1.21.11）
- **flag**：`0xGame{56448caf-0fbc-41f8-82f4-21d36130a52e}`
- **附件**：—（Minecraft 1.21.11 服务器；环境无 MC 协议客户端库，由人在游戏内执行）

**思路**

5 步，**叙事与漏洞是同一件事**：凭据分散三处、日志直接泄露时间线、越权恢复他人备份（IDOR）拿到门禁码，最后进安全屋读告示牌——所有线索都在场景文本里，不需要任何协议层利用。

**关键步骤**

1. 凭据分散三处——账号 `nightowl`（告示牌 A）、口令 **`watch2026`**（**打印机卡纸**第 2 页，正好呼应手册第 3 页「口令自己找，总有人贴在**不该贴**的地方」）。
2. `/ops help` 拿到全部子命令。
3. `logs --since 02:50` 建立时间线，**直接泄露**：`02:50:03 backupd scheduled backup #7 stored (owner: chensy, tag: handover-final)`、`03:19:02 door safe-room unlocked with emergency code`。
4. ★ **越权恢复他人备份（IDOR）**：卡纸第 1 页运维公告明说「`backup restore` 模块的**归属校验仍在开发中**」，而 `backup list` 响应末尾特意强调「（**仅显示当前账号名下的备份**）」——`nightowl` 名下只有 `#2`/`#5`，`#7` 属于 `chensy`。用 `/ops backup restore --id 7` 得到**交接文档**：「我搬去安全屋住了…真有天大的事再来：**门禁码 3117**」。
5. `/ops door unlock 3117` 进安全屋，告示牌上即 flag。

**踩坑**

- 「门禁码只存在**交接文档**里，纸上一律不写」是闭环提示。
- 日志显示 `03:19:41 safe-room auto-locked` ⇒ **门会自锁，进去要快**。

**产出**：`notes/48-深夜值班室.md`、`evidence/48-clues.md`

---

### 3.49 · ez_flower

- **分类**：Reverse
- **状态**：✅ 已解出 ｜ 833 分 ｜ 8 解（离线）
- **flag**：`0xGame{WoW_Th3_f1ow3r$_@re_SOo0oo b3@u7ifull!!}`
- **附件**：`attachment6.zip`

**思路**

PE32 console。"flower"是双关 = **花指令**：三处「**永真 `jcc` + 被跨过的 3 字节垃圾**」让线性反汇编错位，跟跳转目标即可恢复，无需 patch。真正的校验是"输入凯撒 +7 后与常量表异或比较"。

**关键步骤**

1. 定位三处花指令（`33c0 xor eax,eax; 7403 je +3; <junk>`）：`0x40106b` / `0x40110e` / `0x401116`；线性反汇编会在 `0x40106f` 错位。
2. 字符串表整表 XOR `0x5a`（密钥就在紧邻的前一字节 `0x40f19f`）。
3. 校验：输入须 47 字符 → `caesar_shift(input, +7)`（仅字母）→ 与 `.rdata:0x40f170` 的 47 字节常量做 `^0x80` 比较。
4. 用 `capstone` 思路手工反汇编，再用 `unicorn` 执行程序自身的 `0x401060` 机器码复核候选 flag。

**踩坑**

- 凯撒函数里的 `sub 0x5a` 很容易读成 **−7**，实际是 **+7**（方向弄反会得到 `0lUoas{KcK_...}` 这种明显不对的结果）。
- 最后用 **unicorn 执行程序自身的 `0x401060` 机器码**复核候选 flag（独立验证，而不是只靠手读汇编）。

**产出**：`scripts/49-solve.py`、`notes/49-ez_flower.md`

---

## 4. 复盘与经验

> 只写**与解题方法有关**的经验：工具选型、证据纪律、判据设计、时间分配与排队策略。

### 4.1 工具与环境缺口

环境缺了不少工具，而规则不允许随意 `pip install`，于是全部改为**手写替代**——结果反而逼出了更强的证据链（手写实现 + 交叉验证）。

| 缺失工具 | 影响 | 当时的替代方案 | 建议 |
|---|---|---|---|
| 无 PDF 工具（`pdftotext`/`pypdf`/`fitz`） | 25 号读不出 PDF 正文 | 自写 PDF 文本提取器（对象表 + `/ObjStm` 流 + `/ToUnicode` CMap） | 赛前预装，或保留该提取器复用 |
| 无 `tshark`/`scapy`/`tcpdump` | 33 号无法解析 pcap | 自写 pcap 解析器（Ethernet→IPv4→TCP→四元组重组） | 赛前预装 |
| 无 `zbar`/`zxing`/`cv2` | 29 号无法解 QR | 自写 QR 解码器（finder 校验 + format BCH + 去掩码 + 之字形取码 + 反交织） | 赛前预装 |
| 无 `upx` | 36 号无法直接脱壳 | Unicorn 直接执行壳 stub（EP `0x40d960` → OEP `0x401cc0`，229 万条指令） | 预装，或备 Unicorn 脱壳脚本 |
| 无 `ffmpeg`/`cv2` | 14 号无法抽帧 | Chromium 逐帧截图（发现 `platform=html5&high_quality=1` 可免登录取 1080p） | 预装完整版 ffmpeg（精简版解不了 H.264） |
| 无 `bs4` | 47 号无法解析 HTML | stdlib `re` + `html` 等效实现 | 赛前预装 |
| 无 `torch` | 41/45 号无法加载 `.pth` | `pickletools` 静态解析 + 手写 `pickle.Unpickler` 回放 `FloatStorage`，纯 numpy 推理 | 赛前预装（且静态解析更安全） |
| 无 `sage` | 12/28 号无法跑数域 / EC | Sage 脚本等价翻译成 `sympy`；自写 EC 运算 | 赛前预装 |
| 无 `wine` | 37 号无法真跑 `.exe` | Unicorn 模拟 PE 内机器码做验证 | 赛前预装 |
| 无 `sshpass` | 42 号无法非交互 SSH | `paramiko` | 赛前预装 |

> 闲置的工具（如 `jq`、异构架构 `qemu-*`）属**正确的不使用**：本场没有对应题型的场景，不必强用。

### 4.2 方法论（可复用）

- **排队策略**：平台**每队同时只允许 2 个动态容器**，这是唯一硬瓶颈。做法是**离线题并行、动态容器题串行化**——先把纯离线分析（写 exploit / 审源码）全部做完，再按 **2 个一波**动用容器收尾，把瓶颈从"人手数量"转移到"已排好的队列"。
- **统一提交入口 + 强制限速**：所有 flag 走同一个提交脚本，**10 次/分钟**硬限速（串行 + 排队等待）并落盘日志，既避免并发打爆额度，也便于事后审计。
- **flag 位置不假设**：pwn 容器 flag 在 `/home/ctf/flag`（16/18/21/22）与 `/flag`（19/20）**都出现过**，脚本一律多路径并试。
- **工具缺口 → 手写替代**：环境缺 `ffmpeg`/`zbar`/`tshark`/`upx`/`bs4`/`torch`/`sage`/`wine` 等，全部改为手写实现（自写 pcap 解析器、自写 PDF 提取器、自写格式化串构造器、Unicorn 脱壳 / 执行真机码等）。
- **证据纪律**：任何结论必须有可复现的一手证据（脚本输出、反汇编、抓包），不接受"应该是这样"。
- **判据设计**：先想清楚"什么样的观测能区分两种假设"再动手；判据错了，穷举也穷不出结果（29、34）。
- **验证习惯**：写出的 payload 一律本地复算 / 断言再打远程（39 回代 23/23 方程、28 验 `d·G==Q`）。
- **结论必须回源核对**：不把"经验"当规则下发（曾有两条错误结论被推翻）。
- **元认知**：不要把自己的逻辑漏洞当成"结构性无解"而停止（32）。

### 4.3 踩坑统计

| 坑 | 出现次数 / 涉及题目 | 根因 | 规避方式 |
|---|---|---|---|
| 在"猜格式"而不是"算答案" | 2 题（8、14），合计 16 次提交 | 缺"何时该停"的判据 | 一旦发现自己在猜格式，立即停下回报 |
| 判据选错导致在错误的搜索空间穷举 | 2 题（29、34） | 判据选择错误 | 先验证判据本身再扩大搜索（29 的真判据是跨通道 LSB 联合分布） |
| 多方法只能验算、不能验建模 | 1 题（12） | 三种方法校验的是同一个写错输入 | 换方法前先换输入 / 模型，对建模本身做独立核对 |
| 凭记忆写 libc 偏移 | 1 题（19） | 未回源核对 | 偏移一律从本地下载的 libc 现取 |
| 把"经验"当规则下发 | 2 条结论（日期格式、flag 路径） | 过期缓存 / 小样本归纳 | 结论必须回源核对，用"参考"而非"必须" |
| 把自身逻辑漏洞当成"结构性无解" | 1 题（32） | 元认知失守 | 停下之前先复述"哪一步是我还没做"，而不是"哪一步不可能" |

### 4.4 下次改进清单

1. 开工前先做一次工具盘点，缺什么当场决定"装 / 手写"；本次上表缺口全部靠手写替代，应提前补齐。
2. 提交前强制二次确认 flag 的字面形态（全角标点、空格、大小写，以及 `+`/`@` 这类易错字符）。
3. 动态容器按 **2 个一波**排队，离线产出先行；提交入口唯一且限速 10 次/分钟。
4. pwn / 远程题的 flag 路径在脚本里列成候选清单，多路径并试。
5. 建立"停损线"：同一题连续 2 次提交未过即停下回报，不再盲试变体。

---

## 附录 A · 附件与脚本清单

| 文件 | 说明 |
|---|---|
| `scripts/1-solve.py` | 1 错位的签名：APISIX HS256 算法混淆伪造 admin |
| `scripts/2-solve.py` | 2 渲染如呼吸一样简单：Jinja2 SSTI → 读 env `FLAG` |
| `scripts/3-solve.py` | 3 一切的开始：五层传参链（GET/POST/Cookie/Referer/JSON） |
| `scripts/4-solve.py` | 4 ez_64：`system()` 通配符绕过字符白名单 |
| `scripts/5-solve.py` | 5 pollute the key：pydash `set_` 污染模块全局 → pickle RCE |
| `scripts/6-solve.py` | 6 漏风的沙箱：`print.__self__` + 名字拼接 + 迭代文件对象 |
| `scripts/7-solve.py` | 7 decode for love：emoji-aes → AES-256-CBC → base64 → 凯撒 7 |
| `scripts/8-solve.py` | 8 RSA永恒花园：模数恢复 + 解密（含 `--search` 重跑 FactorDB） |
| `scripts/9-solve.py` | 9 约会大作战：小阶元素穷举 + CRT 还原私钥 |
| `scripts/11-solve.py` | 11 为美好的密码献上解密：LFSR 周期 31 → nonce 重用 |
| `scripts/12-solve.py` | 12 天使大人：`sympy` 等价复现数域计算 |
| `scripts/15-solve.py` | 15 奇妙杂货铺：负数购买整数下溢 |
| `scripts/16-solve.py` | 16 亦步亦趋：两关 ret2text + 栈对齐垫 `ret` |
| `scripts/17-solve.py` | 17 ！？数学基础？！：Unicode 运算符映射后连答 100 题 |
| `scripts/18-solve.py` | 18 两次回响：9 字节 shellcode 两阶段自覆盖 |
| `scripts/19-solve.py` | 19 保持沉默：fd 生命周期 + ret2libc |
| `scripts/20-solve.py` | 20 三扇门：ret2csu 三条链（SYSTEM / CSU / CSU_WIN） |
| `scripts/21-solve.py` | 21 大道至简：SROP |
| `scripts/22-solve.py` | 22 这怎么可以作为名字啊！：格式化串两轮 + 自写 `build_fmtstr()` |
| `scripts/24-solve.py` | 24 小伊卡：修 IHDR 高度 + 重算 CRC32 |
| `scripts/25-solve.py` | 25 欢迎来到CTF的世界！：自写 PDF 文本提取器（可复用） |
| `scripts/28-solve.py` | 28 ECC之诞生：超奇异曲线 + Pohlig–Hellman + BSGS |
| `scripts/29-solve.py` | 29 Strange_lsb：三通道 LSB 异或 + 自写 QR 解码 |
| `scripts/30-solve.py` | 30 ATP代码实验：取首页参考代码 → 提交 |
| `scripts/32-solve.py` | 32 四月是你的谎言：密钥穷举与验证 |
| `scripts/33-solve.py` | 33 ez_traffic：自写 pcap 解析器 |
| `scripts/34-solve.py` | 34 模糊二维码：板面矫正 + 珠阵提取 + 结构穷举扫描 |
| `scripts/35-solve.py` | 35 signin：常量表 XOR 0x5A |
| `scripts/36-solve.py` | 36 ez_upx：Unicorn 跑壳 stub 到 OEP |
| `scripts/37-solve.py` | 37 云朵：RC4 + Unicorn 交叉验证（`--emulate`） |
| `scripts/38-solve.py` | 38 旧时代的信号：16 位实模式 33 轮解密 |
| `scripts/39-solve.py` | 39 z3_solver：环状线性方程组 z3 求解 + 回代断言 |
| `scripts/40-solve.py` | 40 Guess：PyInstaller CArchive 手解 + XTEA 解密 |
| `scripts/41-solve.py` | 41 ez_pytorch：`pickletools` 静态抠源码 + 手写 4 段解码 |
| `scripts/42-solve.py` | 42 Treasure_island：`paramiko` + 越权 unlink 心跳脚本 |
| `scripts/43-solve.py` | 43 hd_pytorch?：手工拼 zip 容器 + `builtins.eval` 绕过黑名单 |
| `scripts/44-solve.py` | 44 粗心的小x：三段 key 拼接（含 git 历史） |
| `scripts/45-solve.py` | 45 Magical Large Potato!：手写 `pickle.Unpickler` 回放 + numpy 推理 |
| `scripts/46-solve.py` | 46 Interesting_ppt：docProps 元数据 + 重复密钥 XOR |
| `scripts/47-solve.py` | 47 奶蛙的博客：124 页碎片按页序拼接 → gunzip |
| `scripts/49-solve.py` | 49 ez_flower：花指令恢复 + 凯撒 +7 + Unicorn 复核 |

| 附件 | 说明 |
|---|---|
| `app.py`（5、6） | pollute the key / 漏风的沙箱 的服务端源码 |
| `week1 Crypto decode for love.txt` | 7 的四层编码密文 |
| `week1 Crypto RSA永恒花园 .py` | 8 的 RSA 脚本（616 B） |
| `关于邻家的天使大人不知不觉把我惯成废人这档子事.py` | 12 的数域计算脚本 |
| `pwn`（16/18/19/21） | 四个 pwn 二进制（无附件名，平台直接给同名文件） |
| `attachment.zip`（20、22） | 三扇门 / 这怎么可以作为名字啊！ 的题目包 |
| `picture.zip` | 23 的 `eat.jpg`、`night.jpg` |
| `little1kA.zip` | 24 的 PNG |
| `CTF入门指北.pdf` | 25 的 PDF |
| `week1-misc-strange_lsb.zip` | 29 的隐写图 |
| `ez_traffic.zip` | 33 的 pcap |
| `QRcoooold.zip` | 34 的 `QRcoooold/messyQR.jpg` |
| `signin.zip` / `attachment1.zip` … `attachment6.zip` | 35–39、49 的 Reverse 题目包 |
| `attach.zip` | 41 的 `.pth` |
| `AI-chat-project.zip`（含 `chat_export.json`） | 44 的泄露工程 |
| `Magic_Large_Potato.zip` | 45 的 `.pth` |
| `0xgame.zip` | 46 的 pptx |

## 附录 B · 术语与缩写

| 缩写 | 全称 / 含义 |
|---|---|
| SSTI | Server-Side Template Injection，服务端模板注入 |
| RCE | Remote Code Execution，远程命令执行 |
| IDOR | Insecure Direct Object Reference，越权访问对象 |
| SROP | Sigreturn-Oriented Programming，用 `rt_sigreturn` 布置寄存器 |
| ret2text / ret2libc / ret2csu | 返回到程序自身代码 / libc 函数 / `__libc_csu_init` gadget |
| CSU | `__libc_csu_init`，`pop rbx/rbp/r12-r15` + `call [r15+rbx*8]` 的万能 gadget 来源 |
| OEP | Original Entry Point，加壳程序的原始入口点 |
| LSB | Least Significant Bit，最低有效位（隐写常用） |
| QR / finder pattern | 二维码 / 二维码三个定位图形（1:1:3:1:1） |
| IHDR / IDAT | PNG 的图像头数据块 / 图像数据块 |
| EXIF | 图像元数据（含 `Make`/`Model`/`DateTimeOriginal`） |
| POI | Point of Interest，地图兴趣点（高德地图上的地点全名） |
| SRT | 视频字幕文件格式（用于录播全文检索） |
| DASH | B 站的分片流协议（m4s，替代整包 mp4 下载） |
| CMap / CID | PDF 字体字符映射（`/ToUnicode`）/ 中文子集字体编号 |
| DH | Diffie–Hellman 密钥交换 |
| CRT | Chinese Remainder Theorem，中国剩余定理 |
| BSGS | Baby-Step Giant-Step，离散对数求解 |
| ECDSA nonce | ECDSA 每次签名所用的随机数 `k`（重用即泄露私钥） |
| LFSR | Linear Feedback Shift Register，线性反馈移位寄存器 |
| XTEA / RC4 | 两种对称加密算法（本题里都用于硬编码常量解密） |
| pickle / `.pth` | Python 序列化格式 / PyTorch 模型文件（新版为 zip 容器） |
| state_dict / MLP | PyTorch 权重字典 / 多层感知机 |
| CArchive | PyInstaller 打包归档格式（`MEI\x0c\x0b\x0a\x0b\x0e` 魔数） |
| MD5 length extension | 长度扩展攻击（已知 `md5(k‖m)` 可推出 `md5(k‖m‖pad‖x)`） |

