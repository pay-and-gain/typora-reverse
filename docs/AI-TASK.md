# 交给 AI 执行的任务书

> 这份文件的设计目的是：**整份复制给任意具备本地 shell 的 AI，它就能独立完成整个流程**，不需要来回追问。
> 所有判定点都给了可执行的验收命令，不要凭感觉跳过。

---

## 0. 任务定义

**目标**：对 `Typora 1.13.7`（Windows 便携/安装目录）实现「任意机器首次启动自动完成授权」。

**输入**：
- 样本目录 `SAMPLE_DIR`，其下含 `Typora/Typora.exe`
- 一台 Windows 机器，具备 Node.js（≥16）与 PowerShell
- **不需要管理员权限**（全部改动落在用户作用域）

**产出**：
1. 改写后的 `Typora/resources/app.asar`
2. 可分发的 zip（`Typora` 目录 + 说明文档）
3. 运行日志证据（`hook.log`）

**绝对禁止**：
- 重打包整个 asar（风险高，没必要）
- 修改 `.jsc` 字节码
- 触碰 `Typora.exe`
- 关闭 `License Info` 窗口或用 `webContents.reload()`（会直接杀掉进程，见 §7）

---

## 1. 阶段一：侦察（每步都必须通过，否则停）

### 1.1 确认版本

```powershell
Get-Content "$SAMPLE_DIR\Typora\resources\package.json" | Select-String version
```
**判定**：`"version": "1.13.7"`。版本不符则本文所有偏移和常量都需要重算，直接终止。

### 1.2 解析 asar 布局（禁止硬编码偏移）

asar 结构：`UInt32LE` 头部长度 + header JSON + padding + 数据区。头部 JSON 的起始位置随构建而变，**不要假设固定偏移**，直接从头部区域做正则提取：

```js
const buf = fs.readFileSync(ASAR);
const head = buf.subarray(0, 8192).toString("latin1");
let sum = 0;
for (const m of head.matchAll(/"size":(\d+)/g)) sum += Number(m[1]);
const dataStart = buf.length - sum;                       // 数据区起点
const mEntry = head.match(/"launch\.dist\.js":\{"size":(\d+),"offset":"?(\d+)"?/);
const LSIZE = Number(mEntry[1]);
const LOFF  = dataStart + Number(mEntry[2]);
```

**判定**：`buf.subarray(LOFF, LOFF+LSIZE)` 必须包含 `require("./atom.compiled.dist.jsc")`。
本样本参考值：`dataStart=1060`、`LOFF=382355`、`LSIZE=16220`。**仅用于对照，不可写死。**

### 1.3 计算本机指纹

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid
```

```js
fp = sha256(guid + "typora").digest("base64").slice(0, 10).replace(/[/=+-]/g, "a")
```

**判定**：与 `hook.log` 中 `fn_0211-like fingerprint = ...` 一致。注意替换字符是 `"a"`，不是空串——抄错就全盘失败。

### 1.4 确认公钥槽位可替换

```js
const keys = [...asar.toString("latin1")
  .matchAll(/-----BEGIN PUBLIC KEY-----[\s\S]{200,1200}?-----END PUBLIC KEY-----/g)].map(m => m[0]);
```
**判定**：样本内应只有 1 个公钥块（若为 0，说明客户端不在此处验签，任务前提不成立，终止）。

---

## 2. 阶段二：生成密钥对与授权载荷

```js
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding:  { type: "spki",  format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
```

载荷 JSON（≤245 字节，实测 188 字节可用）：

```json
{"email":"typora@local","license":"W4Z8D5-PARZG2-7SLDF9-8QMJ9V","fingerprint":"<本机指纹>",
 "deviceId":"00000000-0000-0000-0000-000000000000","version":"1.13.7","date":"<M/D/YYYY>"}
```

签名：`crypto.privateEncrypt({key: PRIV, padding: RSA_PKCS1_PADDING}, buf)` → 256 字节 → base64（344 字符）。

**判定（强制）**：用公钥 `publicDecrypt` 解回来，必须与原文逐字节相同。不验证等于赌博。

### 2.1 UI 入口的格式陷阱

主界面（Email / Re-enter Email / 序列号）走的是**联网校验** `Setting.activate()`，粘离线码必然报「请输入正确的序列号」。

真正的入口是点「离线激活」后的 `Activation Token` 输入框，其逻辑：

```js
onChange: e => { "+" == t[0] && "#" == t[t.length-1] && onOfflineActivation(t) }
// 内部：token = token.substr(1, token.length - 2)
```

**结论**：粘贴内容必须是 `+` + 344 字符 base64 + `#`，共 346 字符。只给 `+base64` 会砍掉末尾的 `=`，密文变 257 字节，解密直接失败。

---

## 3. 阶段三：改写 launch.dist.js

**策略**：保留原 loader 尾部，只在开头插入 hook。模板取自 asar 内的 `launch.dist.bak.js`（原始未改版，1383 字节），锚点拼接：

```js
const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
const newText = bakText.replace(ANCHOR, HOOK.trim() + ";" + ANCHOR);
```

这样 `.jsc` 字节码加载逻辑逐字节不变。新代码长度必须 ≤ `LSIZE`，超出说明需要重打包，**本任务范围外，终止**。

### 3.1 hook 必须实现的四件事

**① 完整性重定向**：客户端会 SHA256 校验 `launch.dist.js` 自身。让所有对它的读取返回备份内容：

```js
const RB = fs.readFileSync.bind(fs);
const BAK = RB(path.join(__dirname, "launch.dist.bak.js"));
const isLd = p => p != null && path.basename(String(p)).toLowerCase() === "launch.dist.js";
```
必须同时 patch `fs` 与 `original-fs`，覆盖 `readFileSync` / `readFile` / `promises.readFile` 三个入口。

**② 公钥替换**：包装 `crypto.publicDecrypt`，把自己的 PEM 顶上去，解不开时回退原公钥（避免把其他调用打崩）。

**③ fn_0212 不透明校验**：客户端内置一段 256 字节密文，解密后与硬编码明文比对。本样本常量：

```js
const INTEG_EXPECTED = "pvyXdYxWo0HsOVIEo4RFsMiWAmuDpJZ4TZeO0g9ecBchHm86UjJZZftJ2QWkuqlFKPWNbI8lkusRKlRT9SPun07e9mhQ1lZeiojs";
const INTEG_HEAD = [168,163,144,221,123,254,219,133,103,114,95,163,156,84,26,17];
```
两处短路：`publicDecrypt` 命中该密文直接返回期望明文；`Buffer.prototype.equals` 命中该明文强制返回 `true`。

**④ 捕获 IPC handler**：为自动注入铺路：

```js
const ip = require("electron").ipcMain;
const oh = ip.handle.bind(ip);
ip.handle = function(ch, fn){ if (String(ch) === "offlineActivation") OFF = fn; return oh(ch, fn); };
```

### 3.2 写入与校验

```js
if (bytes.length > LSIZE) throw new Error("超出槽位");
new vm.Script(newText);                       // 语法自检
const padded = Buffer.alloc(LSIZE, 0x0a);     // 换行填充，JS 允许尾部空白
bytes.copy(padded, 0); padded.copy(buf, LOFF);
```

**判定**：写回后重读该区域，头部是 `"use strict"`，尾部仍含 `require("./atom.compiled.dist.jsc")`。

> 写入前必须备份 `app.asar`。**注意 PowerShell 的 `-Filter 'app.asar.*'` 会把 `app.asar` 本体也匹配进去**，清理备份时用精确路径，不要用通配。

---

## 4. 阶段四：应对启动续期（本任务最难的一环）

### 4.1 现象

激活成功、重启后回到未激活。日志时序：`hasL: true` → 300ms 内 `[renewL]: unfill due to renew fail` → 授权被清空。

### 4.2 已确认的事实

客户端每次启动 POST `typoraio.cn/store`，请求体：
```json
{"v":"win|1.13.7","license":"<序列号>","l":"<deviceId>","u":"<uuid>","type":""}
```
服务器查不到该 license 即回绝，客户端执行 unfill。**这是服务端行为。**

### 4.3 已验证无效的思路（不要浪费时间）

| 尝试 | 结果 |
|---|---|
| 把载荷 `date` 推到未来 | 仍 unfill，续期不依据该字段 |
| 载荷补 `type` 字段 | 请求体变化，服务器照拒 |
| 断网 / 改 hosts | 任何失败走同一分支，同样 unfill |

### 4.4 有效方案：自动重注入

在 hook 里用捕获到的 handler，启动后多次提交一份新签的授权：

```js
[300, 700, 1200, 2000, 3500, 6000, 10000].forEach(t => setTimeout(() => inject(t), t));
```

`inject` 内部：
```js
const wc = BrowserWindow.getAllWindows().find(w => !w.isDestroyed())?.webContents ?? null;
const ev = { sender: wc || DUMMY, reply(){}, senderFrame: null, ports: [] };
Promise.resolve(OFF(ev, token)).then(r => log(r));
```

**判定**：`hook.log` 出现 `activate t300 -> [true,"","<email>","<license>"]`。

### 4.5 如果要分发给别人

硬编码单机 token 无意义（绑定 MachineGuid）。改为**运行时签名**：每次启动读本机 GUID → 算指纹 → 现签 → 注入。这样同一个包在任何机器上都能自动激活，代价是私钥必须随包走。

---

## 5. 验收标准（缺一不可）

| # | 检查项 | 期望 |
|---|---|---|
| 1 | asar 内嵌公钥 | 等于自己的 `public.pem` |
| 2 | 私钥/公钥配对 | 成立 |
| 3 | 授权回环 | 解密结果与原文逐字节相同 |
| 4 | 密文长度 | 恒 256 字节 |
| 5 | 明文长度 | ≤ 245 字节 |
| 6 | 指纹 | 与 `hook.log` 中 fn_0211 预测值一致 |
| 7 | asar 写后 | 区域含 loader 尾部，填充仅 `\n` |
| 8 | 启动后 `hook.log` | 出现 `activate t300 -> [true,...]` |
| 9 | 启动后 `typora.log` | `hasL: true`，注入晚于 `unfill` |
| 10 | 进程 | 存活，窗口标题为 `Typora` 而非 `License Info` |

---

## 6. 排错表

| 现象 | 根因 | 处理 |
|---|---|---|
| 「请输入正确的序列号」 | 粘在主界面联网通道 | 改走「离线激活」→ Activation Token |
| `Invalid Activation Token` | 首尾不是 `+` / `#` | 严格 `+…=#` |
| 解密失败 / 257 字节 | 末尾 `=` 被 `substr` 砍掉 | 补 `#` 收尾 |
| 激活成功但重启失效 | renew 清空 | 上 §4 |
| 启动即退出 | 关了 `License Info` 或早期 reload | 删掉这两个动作 |
| 白屏 / loader 报错 | 覆盖破坏了 `.jsc` 加载尾部 | 从备份还原 |
| 换机器失效 | 指纹绑定 | 改用运行时签名 |
| `guid fail` 日志 | `reg query` 读不到 MachineGuid | 检查注册表权限 |

---

## 7. 三个会导致应用直接退出的坑（真实踩过）

1. `win.close()` 关掉 `License Info` 窗口 → 该窗口带 `quitOnClose`，关闭即 `app.quit()`，进程数归零。
2. 窗口初始化阶段 `webContents.reload()` → 进程被杀。
3. 用 `Get-ChildItem -Filter 'app.asar.*' | Remove-Item` 清理备份 → 会把 `app.asar` 本体一起删掉（Windows 通配怪癖）。清理一律用精确路径。

---

## 8. 交付物清单

```
app.asar                     改写完成，含换公钥 + 完整性绕过 + 自动注入
hook.log                     验证证据（分发前必须删除，含本机 GUID 与路径）
README.txt                   面向使用者的说明（含免责声明）
themes/                      可选，主题文件
```

分发前必须从包内移除：`private.pem`、`public.pem`、`activation.txt`、`hook.log`、`*.bak`、`_asar_*` 中间目录。

---

## 9. 参考

完整逆向手册（偏移表、字符串常量、时序、更多细节）见同目录 `REVERSE_HANDBOOK.md`。
