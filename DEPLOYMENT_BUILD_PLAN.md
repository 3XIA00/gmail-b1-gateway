# 部署态一键授权 · 运行时侧实现计划 v0.2（plan-first，未动代码）

> **v0.2（2026-09-02）**，依 Chris QA（msg_d61040a9）+ 测试姬 断言/边界 review（msg_fa332f51 / msg_4aa5c5e5）增补：
> §4 命名 (f)-operational 的 **lag-window 残留**；§1.3/§9 加**部署路 expected_sha256 非空守卫**；
> §5 突变族显式含 `0x1A/0x0A/CRLF`；§9 钉 **(b) diff-boundary 契约**（touch-set + 4 锁定 blob 不动）；
> §3 加 **A2.2 confirm 的 c1/c2 接缝验收**（测试姬 msg_4aa5c5e5 发现 + Chris msg_37e4e5d7 定为 gate-required canonical 措辞：`confirm` 须绑定「入站网络/agent 消息/channel event 均不可满足」的设备本地人肯定源，暴露给 c2 接缝）；
> §8 加 **(f)-operational 缓解(b) 具名 owner** 待定；§3/§5 折进 测试姬 A2.1-2.4/A1.1-1.3。v0.1 正文其余保留。

> 阶段：T+0 真发 POC 已闭（CONNECT/SEND 双 PASS）。本计划覆盖**部署态一键授权**
> 中 JARVIS 明确划给我的**运行时侧**（gmail-gateway repo 内）：
> bundled-client 加载器 + 内容 hash 校验 fail-closed + 本地 trigger 接入现有
> loopback/PKCE。**不含**把 JSON 打进 daemon 安装包 / 装机签名校验（= puffo-agent
> 安装基础设施，跨 repo/跨 team，JARVIS 之后与 Jeremy 定 owner）。
>
> 对齐：DESIGN.md v0.1（`45925f6d…`）+ IMPLEMENTATION_PLAN v0.2。
> 工作语言 Python（与已交付模块一致）。**本计划先不动代码**——出稿后 ping Chris
> 走 (a)-(f) 轴形状，再 commit 设计 / 落码。

---

## 0. Scope 边界（Chris 的 axis (c) 拆分，逐字对齐）

| 项 | 归属 | 内容 |
|---|---|---|
| **(c1) 运行时载入完整性** | **我 · 本计划** | daemon 从已知路径读 bundle + 校验内容 hash 对齐钉死的期望值 + 不符 fail-closed。gate：探测测试改 bundle 一个字节 → 载入 fail-closed，无部分状态。 |
| **(c2) 装机期 bundle 生产 + 安装签名** | **不是我 · 已延后** | 把 JSON 打进安装包、装机签名体系。JARVIS 与 Jeremy 定 owner/repo 后，Chris 在那侧单设 gate。 |

**接口即桥**：我为 (c1) 定的契约（bundle 放哪 / hash 长什么样 / loader 入口）
就是 (c2) 上游必须满足的对接面——契约干净，跨 repo gate 才可设计。

---

## 1. 接口契约（JARVIS 点名要的三件——本计划头号交付物）

daemon 侧不必真实存在即可设计/测试；先假定「已知路径下有 bundled JSON + 对应期望 hash」。

### 1.1 bundle 放哪
延用 `gateway/paths.py` 的 data-root 单一来源约定（现有 `token_db`/`proposals_db`/
`audit_db`/`payloads_db` 同款），新增一条：

```
client_bundle(data_root) -> <data_root>/client/client.json
```

(c2 的安装器负责把 bundled client JSON 落到这条路径；运行时只读、绝不写。)

### 1.2 期望 hash 长什么样 + **它的信任根在哪**（载重决策）
- **格式**：bundled JSON **文件原始字节**的 `sha256` 小写 hex。**读 `rb`、哈希裸字节、
  零换行转码**（吃过 keystore 文本模式 `0x1A`/`0x0A` 的亏，见 IMPL_PLAN §2 L77）。
- **期望值从哪来（信任根）**——这是必须写进纪录、由 Chris 拍板哪层载重的点：
  - **v1 推荐：编进 gateway 代码常量**（`EXPECTED_CLIENT_SHA256`）。pin 随**已签名的
    daemon 二进制**走 → 它的真伪由 (c2) 装机签名覆盖，不额外落一个可被同步篡改的文件。
    换共享 client = 一次代码发布（正是 cert-pin 该有的刚性）。
  - **备选：manifest 文件**（`<data_root>/client/client.manifest.json` 存期望 hash），
    真伪同样**只能靠 (c2) 的签名覆盖 manifest**。
- **诚实边界**：我的 (c1) loader 只能保证「盘上 JSON == hash H」；**H 本身可信 ⟸ (c2)**
  （代码常量也好、manifest 也好，信任根都落在装机签名/代码完整性 = c2）。loader 不冒充
  「H 是对的」——它只做 fail-closed 的字节匹配 + 留干净口子让 c2 供 H。

### 1.3 daemon 怎么调 loader（入口）
```
load_bundled_client(bundle_path: str, expected_sha256: str)
    -> tuple[client_id: str, client_secret: str | None]
```
- 读 `bundle_path` 裸字节 → 算 sha256 → 与 `expected_sha256` **常量时间比对** →
  不符 **raise 且零副作用**（不建 DEK、不开 listener、不写 token）→
  相符才**在 bundle.py 内自解析这份已校验字节**（逻辑镜像 `authorize._read_client_credentials`：
  接受 `{"installed":{…}}` 或裸对象、`client_id` 必需、`client_secret` 可选）。
  **不按 path 回调 `_read_client_credentials`**——回调会重读文件 = TOCTOU（测试姬 point），
  且会越出 authorize.py=main-only diff-boundary；自解析同一份内存字节两者兼顾。
- `expected_sha256` 走**依赖注入**（与 repo 现有 DI 风格一致：flow_factory/key_provider
  都是注入的）——所以 v1「代码常量」与备选「manifest」**同一入口两种喂法**，切换不改上层。
- **部署路非空守卫（Chris LOW#1）**：DI 接受注入 ⇒ 必须防「未来 misconfig 把 test-shape pin
  静默注进 prod」。`authorize.main` **部署模式**在跑任何流程前，若 `expected_sha256`
  为空/None/占位假值（testfake）→ **fail closed，零副作用**。gate 见 §5。（dev 路
  `--client-secret-file` 无 pin 概念，不受此约束；守卫只挂部署路。）

**接线**：`gateway/authorize.py:main` 现有 `--client-secret-file`（POC/dev 路）保留；
新增部署路（`--bundled` 或子命令）= `load_bundled_client(paths.client_bundle(root), EXPECTED)`
→ 复用 `run_authorize(...)` **逐字不动**（b493568 锁定核心语义不碰）。最小改动。

### 1.4 c2 handoff checklist（测试姬 msg_69b150d9：两条 c2-侧验收必须随契约过界、被 c2 owner 显式接住）
运行时侧（本 repo）只能锁住每条安全属性的**本地半扇门**；另半扇落在 c2/UI 接线，而 c2 现**无主**（§0：JARVIS/Jeremy 定 owner 后 Chris 单设 gate）。交 §1 契约给 c2 上游时，以下 **c2-侧验收**必须随契约过界、由 c2 owner **显式接住**，不得在 repo 边界只剩 Bob 侧半扇：
- **H 的信任根**（§1.2）：期望 hash 的真伪由 c2 装机签名/代码完整性覆盖——loader 只证「盘上 JSON==H」。
- **A2.2 confirm 源真实性**（§3）：`confirm` 必须绑定「任何入站网络/agent 消息/channel event 都无法满足的设备本地人肯定源」。我侧 `gateway/trigger.py` 单测锁死 confirm-负⇒零副作用；但**「confirm 真绑定了不可远端满足的本地源」由 c2 接线保证**——handler 单测全绿 ≠ prod 接线安全（把 confirm 接到 agent 可触发路径 = A2.2 静默击穿，正是此条防的）。docstring 已写死该要求，需随契约不掉队。

---

## 2. bundled-client 加载器（对 Jeremy「只打包必须字段」）

- **字段最小 · 由构造保证**：现有 `_read_client_credentials`（authorize.py L50-64）
  只读 `client_id`(必需) + `client_secret`(可选)，**其余 5 字段
  （project_id/auth_uri/token_uri/auth_provider_x509_cert_url/redirect_uris）根本不读**。
  所以 bundle 瘦成 `{"installed":{"client_id":"…","client_secret":"…"}}` 即够。
  **必要字段集 = `{client_id, client_secret}`**（测试姬 secretless A/B 实测：省 secret →
  Google token 交换 `invalid_request`、无 token 封存 → `client_secret` 不可去；client_id-only
  分支实测关闭）。符合 Jeremy「只打必须字段」。loader 不新增任何字段要求。
- **不硬编字段（pin 钉实际字节）**：hash 钉的是**那一份实际 bundle 的确切字节**，不是固定
  字段集——一字节变即换 pin、fail-closed。**§1.2 `EXPECTED_CLIENT_SHA256` pin = 带 secret 那份
  bundle 字节**（`{"installed":{"client_id":…,"client_secret":…}}`，即上面实测能换到 token 的那份）。
  loader 与字段形状无关（pin 驱动），故 with-secret / 未来任意合法形状都无需为分支改码。
- **fail-closed 先于一切副作用**：hash 校验在 `run_authorize` 之前，校验不过 → 直接 raise，
  DEK 不 provision、loopback 不 bind、token 不 seal。

---

## 3. 本地 trigger / deep-link（build target = 测试姬 `DEEPLINK_TRIGGER_ASSERTIONS_gmail.md`；Chris axis (d) 已 1:1 letter-confirm）

一键流：Puffo UI「连接 Gmail」按钮 → `puffo://authorize` deep-link → OS 路由到 daemon →
**设备本地确认对话框** → 用户确认 → daemon 跑现有 loopback/PKCE authorize（用 §2 已校验的
bundled client）→ 浏览器内完成 Google 同意。

**运行时侧我负责的 = deep-link handler 逻辑**（URL scheme 注册 + 确认 UI 本体属 daemon/
安装侧 = c2/UI，不在此）。设计成可注入、可单测：
```
handle_authorize_trigger(uri, *, confirm: Callable[[], bool], authorize: Callable[[], None])
```
**照建 测试姬 断言集（property 级，她 owns、Chris axis (d) 已 1:1 letter-confirm）**，逐条即我的测试目标：
- **A2.1 确认在先、网络在后**：未召唤 invoke → 本地人确认返回肯定前 **既不 open browser 也不 bind loopback**。（比我初稿「不 open browser」更严，采纳「连 listener 都不 bind」。）
- **A2.2 确认必须设备本地 UI**：不得由频道/agent 入站消息满足（防远端/agent 代批）。
  **⚠ c1/c2 接缝（测试姬 msg_4aa5c5e5 新发现，同 hash H 类）**：handler 侧只能证「confirm 肯定前不 open/不 bind」（A2.1/A2.3，可单测）；但 **A2.2 的实质——`confirm` 绑定的是「无任何入站网络/agent 消息可满足的设备本地人肯定」——落在 c2/daemon 怎么接 `confirm`**。风险：单测喂 fake confirm 照过，而**生产接线若把 `confirm` 接到 agent/网络可触发路径，A2.2 被击穿、单测仍绿**。→ `handle_authorize_trigger` 契约**显式写死一条对 c2/UI 的验收（Chris msg_37e4e5d7 定为 gate-required，canonical 措辞）**：调用方 MUST 把 `confirm` 绑定到「**任何入站网络消息 / agent 消息 / channel event 都无法满足**的设备本地人肯定源」——写进 `handle_authorize_trigger` docstring + §3 显式验收（与 §1.2「H 信任根在 c2」并列）。像 hash H 一样把安全验收暴露给 c2 接缝，**不当纯可注入回调**。两层门：我侧单测证 confirm-负 ⇒ 零副作用；c2 侧证 confirm-源真实性，互不替代。walkthrough deeplink 1:1 锁进契约。
- **A2.3 拒绝/超时 → fail closed**：无残留 listener、无 token 面。
- **A2.4 知情确认**：提示须说明在授权什么（`gmail.send` + 账号语境），防盲批。
- **A1.1 同设备 + 仅 loopback redirect**：trigger 与 loopback receiver 同设备；非 `127.0.0.1`/`localhost` redirect MUST 拒（fail closed）。
- **A1.2 deeplink payload 不变式**：deeplink **不带 token/code/secret、不能注入 `redirect_uri`**；网关照旧自建 loopback。测：deeplink 带构造 `redirect_uri`/`code` → 必须被忽略。client 也永远是 §2 bundled+已校验那份（与 hash-pin 从两个方向共同守 swapped-client_id 载重攻击面）。
- **A1.3 保住 b493568 loopback 不变式**：`bind((host,0))` + `_is_loopback` + 网关自生成 redirect 在 deeplink 路径不被绕过。

（我初稿 3 条 ⊂ 此集：不授予=A2.1、不注入 client/redirect=A1.2、本地来源=A2.2/A1.1。以她的文件为准建。）

---

## 4. Axis (f) 决策（Chris 要求：纪录必须写明哪层载重）

Chris 给了两选项。我的**明确推荐：v1 由 (f)-operational 载重**，理由：
- **loader 本地观测不到 Google 的 app-verification 状态**——Google 不向 client 暴露审核态；
  同意页的 publisher 只有**人/测试姬 在同意时**看得到。所以「daemon 定期校审核新鲜度」
  必然要 Puffo 运营一个**云端签名 attestation 端点**——(a) 是新云依赖，(b) 与已延后的
  跨设备 broker 基础设施重叠，(c) 属安装/云侧，**不在我 gmail-gateway 运行时 scope**。
- 故 **v1**：loader **不**对 app-verification 新鲜度设门（本地测不了）；新鲜度不变量由
  **运营层**担（审核失效时 revoke / 停发安装）+ **测试姬 tier 的同意页-publisher 探测**。
- **留干净 seam**：loader 入口可在未来**加一个注入的 freshness 校验**（(f)-runtime），
  但 v1 **不建**（避免臆造云依赖）。
  - **若未来选 (f)-runtime（Chris 已定为硬验收）**：freshness/attestation 端点 MUST NOT
    carry / echo / refresh / 触碰 OAuth token 或 authz code；一旦碰 token 即塌回被 defer 的
    cross-device broker custody 审查、须重过那个 gate（测试姬 提，Chris letter-confirm 为硬门，非软偏好）。
- **前置依赖（模型级，安全关键——非可选加固）**：共享 client 必须是 Google 已验证 + 持续
  维护验证的 app——PKCE 拦不住可提取/可冒充的共享 client_id，唯一守卫是 Google 对共享 app 的
  验证 + 同意页 publisher 展示。这条是 (f) 的前提，(f)-operational 正是它的运营落点。
  **实测背书（测试姬 secretless A/B）**：省掉 client_secret 后 Google 直接 `invalid_request`
  ——证明「PKCE-alone 守 client」这条假设从未在桌面上，**Google 验证是安全关键属性、非 nice-to-have**；
  Jeremy owner 的 (f)-operational Console 校验周期正与之等比。

- **已记录残留（Chris msg_d61040a9 要求显式命名，否则「operational 载重」会被读成「已解决」）**：
  operational 载重 ⇒ 「Google 验证失效」与「运营方 revoke/停发安装」之间存在 **lag window**；
  该窗口内的**新安装会在未验证 client 下完成授权**。这是 **v1 已知接受残留**，缓解：
  (a) 测试姬 onboarding 同意页-publisher 探测（抓 per-user）+ (b) 运营方监控共享 client 验证态。
  若残留变得不可接受 → 补救即 (f)-runtime——**在本 repo 之外**。

> 纪录结论：**v1 axis (f) 载重层 = operational**（doc 定 revoke/停发行为 + 测试姬 同意页探测 +
> 上述 lag-window 残留已命名）；code 侧 v1 无 (f) 属性，只留注入 seam。若 Chris/Jeremy 要
> (f)-runtime，那是 c2/云侧新工作。

---

## 5. 测试策略（sole 我可独立测的运行时侧；沿用 hypothesis + 正/反例）

- **(c1) load 完整性**：
  - 正：正确 bundle → `(client_id, secret)` 正确；瘦 bundle 无 secret → `(client_id, None)` 且校验过（secretless 分支）。
  - 反（gate）：**property——任意单字节突变** bundle → raise **先于任何副作用**
    （断言 DEK 未建、listener 未 bind、token 未写；无部分状态）。
  - **突变族显式覆盖（Chris LOW#2）**：随机字节 hypothesis 会**欠采样**零转码子句要防的那类
    ——故 property 显式含 **注入/翻转 `0x1A`、`0x0A`、`CRLF` 窗口**的突变用例（keystore 文本模式
    先例：正是这几个字节触发过静默截断/撑大），不能只靠随机字节。
  - 二进制模式回归：带/不带尾随换行 = 两个不同 hash，两者都可钉（**零转码**）。
  - hash 比对常量时间。
  - **部署路守卫 probe（§1.3）**：部署模式启动时 `expected_sha256` 空/None/testfake → **fail closed
    先于任何副作用**（DEK/listener/token 皆未动）。
- **(d) trigger 不变量**：照建 测试姬 A2.1-2.4 / A1.1-1.3（§3）——`confirm()`→False ⇒ 无 browser-open、无 loopback bind、`authorize()` 零调用（A2.1/A2.3）；`confirm` 不接入站消息来源（A2.2）；deeplink 带构造 `redirect_uri`/`code` 被忽略、client 永远 bundled（A1.2）；非 loopback redirect 拒（A1.1）；b493568 loopback 不变式在此路径存活（A1.3）；malformed URI 拒。
- **字段最小**：loader 对缺失的 5 个非必需字段不报错（对 Jeremy「只打包必须字段」的验收）。
- 这些**全在 gmail-gateway 内可跑，不需真 daemon/安装包**（JARVIS 放行的独立性）。
- 运行时真发观测（连真 Google、落地确认）仍属 **测试姬 tier**，我这层是 code-时门，两层不互替。

---

## 6. Gate-轴覆盖图（走 walkthrough 用）

| 轴 | 本计划落点 | 状态 |
|---|---|---|
| (c1) load 完整性 | §1.2/§1.3/§2/§5 | 已具体 |
| (d) deep-link/trigger | §3/§5 | 已具体；测试姬 A2.1-2.4/A1.1-1.3 折进，Chris (d) 1:1 confirm |
| (f) 验证新鲜度 | §4 | operational 载重 + lag-window 残差 + seam；Chris PASS，(b)-owner=Jeremy |
| (a) Desktop-type | §4/§7 | = 测试姬 onboarding 同意页 probe（gateway 内测不了），非 code-gate |
| (b) 锁核 diff-boundary | §9 | 契约已钉（touch-set + 4 blob 不动）；gate=PR diff（Chris code-tier，task #33） |
| (e) 同设备 fail-closed | §3/§5 | = 测试姬 A1.1，无补充 |

---

## 7. Tradeoffs / 诚实边界

- **H 的信任根 = c2**（装机签名/代码完整性），(c1) 只保证「盘上 JSON==H」——不冒充更强。
- **同 UID**（IMPL §2.6）：v1 记录不解决，共享 OS 用户下文件权限非硬隔离。
- **模型前置（安全关键）**：共享 client 必须 Google 验证 + 持续维护——(f)-operational 的存在前提。
  测试姬 secretless A/B 实测背书：省 secret → `invalid_request`，故 Google 验证是安全关键属性、非可选加固。
- **pin 刚性**：v1 pin 编码进 daemon 二进制 → 换 client 需发布；这是安全 pin 应有的取舍。
- 跨设备授权：本阶段不做（Jeremy「跨设备先不考虑，先按初版走」）。

---

## 8. 我需要别人给的

- **JARVIS/Jeremy**：(c2) owner/repo 定案（我把 §1 契约交出去后）——交界时**务必带上 §1.4 handoff checklist**（H 信任根 + A2.2 confirm 源真实性两条 c2-侧验收）。
- **(f)-operational 缓解(b) 具名 owner = Jeremy（已认领 msg_088a55ce，JARVIS msg_45c61c13 记录）**，
  **周期已钉 = 低量期每月一次 + 收 Google 验证邮件即办（Jeremy msg_a34448c6 确认测试姬建议量级）**；
  操作性、无 code 影响，PR 时已并入 §4。
- **测试姬**：deep-link 断言**已交付**（`DEEPLINK_TRIGGER_ASSERTIONS_gmail.md`，已折进 §3/§5，Chris 已 1:1）；
  **secretless 操作测试结论已交付**（msg_212c6f0e，RESULT=FAIL：省 secret → `invalid_request`、无 token 封存）
  → **§1.2 pin = 带 secret 那份 bundle 字节**，client_id-only 分支实测关闭（见 §2）。
- **Chris**：先走 (a)-(f) 轴形状（他 offer 的 walkthrough），再 commit 设计/落码；(f) 载重层拍板；(a)(b)(e) 定义。

---

## 9. 落地顺序 + (b) diff-boundary 契约（walkthrough 锁定后才动码）

### (b) diff-boundary 契约（Chris axis (b)，walkthrough 前先钉、PR diff 为证）
**允许触碰的 touch-set（穷举，多一个都要先报）**：
- `gateway/paths.py` — 加 `client_bundle(data_root)`（纯新增函数，不改现有 4 条）。
- **新文件** `gateway/bundle.py` — `load_bundled_client()` + hash 校验（**自解析已校验字节**，镜像 `_read_client_credentials` 逻辑，不按路径回读 → 无 TOCTOU + 保 authorize.py main-only）。
- **新文件** `gateway/trigger.py` — `handle_authorize_trigger()`（注入 confirm/authorize）。
- `gateway/authorize.py` — **仅** `main` 加部署路 + 非空守卫；`run_authorize`/`_read_client_credentials` **逐字不动**。
- 对应 `gateway/tests/` 新增测试文件（新增，不改现有）。

**MUST NOT 动的 b493568 锁定 blob（blob-identity 不变）**：
`gateway/tests/test_send_path.py`=`cb214b77` · `gateway/tests/test_supervisor.py`=`14763940` ·
`store/ledger.py`=`5cbdb013` · `gateway/supervisor.py`=`8ec19f26`。verb set 仍 `{authorize, send}`
（部署路是 `authorize` 的模式开关，非新 verb）。**gate = 实际 PR diff 证明 touch-set 不越界。**

### 落地顺序
1. `gateway/paths.py` 加 `client_bundle(data_root)`。
2. `gateway/bundle.py`：`load_bundled_client()`（hash fail-closed + **自解析已校验字节**，镜像 `_read_client_credentials` 逻辑；避免 TOCTOU + 保 authorize.py main-only）+ 单测（§5 (c1)，含 0x1A/0x0A/CRLF 突变族 + 部署守卫 probe）。
3. `authorize.main` 加部署路（复用 `run_authorize` 不动）+ 非空守卫。
4. `gateway/trigger.py`：`handle_authorize_trigger()`（注入 confirm/authorize）+ 不变量单测（§5 (d)，照 测试姬 A2.1-2.4/A1.1-1.3）。
5. 全绿 + PR diff 证 touch-set 不碰 4 锁定 blob → 交 Chris code-时门 + 测试姬 运行时。

### 落地状态 = BUILT（2026-09-03，git 未初始化；blob-id 由 `git hash-object` 独立算）
touch-set（穷举，与上面契约逐条对上）：
- `gateway/paths.py` `cc6583a9763f` — 加 `client_bundle()`（纯新增）。
- `gateway/authorize.py` `aec39dfc9fe6` — **仅** `main` 加 `--bundled` 部署路（`--client-secret-file` 与 `--bundled` 互斥必选其一）；`run_authorize`/`_read_client_credentials` 逐字不动。
- **新** `gateway/bundle.py` `a8a4d4958fef` — `load_bundled_client()`：pin well-formedness 守卫（None/空/非-64-hex/全零 → fail-closed，**先于开文件**）→ raw-bytes `sha256` + `hmac.compare_digest` → 自解析已校验字节。`EXPECTED_CLIENT_SHA256=None`（c2 未钉前部署路 fail-closed）。
- **新** `gateway/trigger.py` `08144daa7c62` — `handle_authorize_trigger()`；docstring 写死 A2.2 canonical 验收（confirm 必须设备本地人肯定源、不可远端满足）。
- **新** `gateway/tests/test_bundle.py` `c3110b4fb9f3` + `gateway/tests/test_trigger.py` `e789c6f57e58`。

**b493568 锁定 blob 已核 = 全部逐字节不变**：`test_send_path.py`=`cb214b77` · `test_supervisor.py`=`14763940` · `store/ledger.py`=`5cbdb013` · `supervisor.py`=`8ec19f26`。verb set 仍 `{authorize, send}`（`__main__.py` 未动）。

**测试**：新增 39 测试全绿；全套件 **323 passed**。§5 覆盖点：单字节突变 property（hypothesis）+ 显式 0x1A/0x0A/CRLF 突变族 + LF→CRLF 回归 + 部署守卫 probe（空/testfake/全零 pin fail-closed 先于开文件）+ secretless 解析分支 + `authorize.main --bundled` 未钉/失配 pin fail-closed 且不封 token。→ 待 Chris code-时门（task #33 残留 = PR diff）+ 测试姬 运行时。
