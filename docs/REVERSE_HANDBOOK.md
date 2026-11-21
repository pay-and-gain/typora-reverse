# Typora 1.13.7 (Windows) 离线激活逆向与持久化 —— 操作手册

> 执行者：任何具备本地 shell + Node.js 环境的 AI 或人。
> 目标样本：`Typora\resources\app.asar`，总长 398826 字节，`package.json` 内 `"version":"1.13.7"`。
> 本文所有偏移、哈希、字符串均来自该样本实测。**换版本必须重新解析，禁止照抄偏移。**
> 原理：不破解验签算法，而是把客户端内置公钥替换为自己生成的公钥，再用配对私钥签发授权。

---

## 0. 结论先行：整个授权链的真实形状

```
服务端（原厂）:          客户端（Typora 主进程）:
  privateEncrypt(PRIV)  →  base64  →  publicDecrypt(PUB)
  产出 256 字节密文                  解出 utf8 JSON
                                     ↓ JSON.parse
                                     ↓ 校验 fingerprint == 本机指纹
                                     ↓ 校验通过 → 写本地授权
```

关键点：

1. 客户端**只做公钥解密**，全程没有任何"向服务器复核签名"的动作，所以换公钥即可完全接管签发权。
2. 算法是 `RSA-2048 / PKCS#1 v1.5`，密文恒为 256 字节，明文上限 245 字节。
3. 授权 JSON 字段（实测可用）：

```json
{"email":"attacker@example.com","license":"W4Z8D5-PARZG2-7SLDF9-8QMJ9V",
 "fingerprint":"<本机指纹>","deviceId":"00000000-0000-0000-0000-000000000000",
 "version":"1.13.7","date":"12/21/2026"}
```
188 字节，安全落在 245 之内。

4. 两个额外的坑（必须先知道，否则必失败）：
   - **完整性自检**：主进程会 SHA256 校验 `launch.dist.js` 自身，并对一段硬编码密文做 `publicDecrypt(...).equals(EXPECTED)`。必须双重绕过。
   - **启动续期（renew）**：每次启动 POST `typoraio.cn/store/...`，服务器查不到伪造 license 就回绝，客户端随即 `unfill`（清空本地授权）。**这是服务端行为，改 date / 改 type 都绕不过**，只能在客户端补回。

---

## 1. 前置信息采集

### 1.1 目标定位

```powershell
$ROOT = "<SAMPLE_DIR>"          # 你的样本根目录
$EXE  = "$ROOT\Typora\Typora.exe"
$ASAR = "$ROOT\Typora\resources\app.asar"
Test-Path $ASAR                           # 必须 True
Get-Content "$ROOT\Typora\resources\package.json"   # 记下 version
```

### 1.2 本机指纹（授权必须绑定它）

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid
```

指纹算法（来自主进程 fn_0211，实测逐字符吻合）：

```js
fp = crypto.createHash("sha256")
      .update(MachineGuid).update("typora")
      .digest("base64").slice(0, 10)
      .replace(/[/=+-]/g, "a");   // 注意是 "a"，不是空串
```

判定标准：算出来的 10 字符，必须和 `Typora\hook.log` 里 `fn_0211-like fingerprint = ...` 一致。

### 1.3 生成自己的密钥对（只需一次）

```js
const crypto = require("crypto");
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa",
  { modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "pem" },
                         privateKeyEncoding: { type: "pkcs8", format: "pem" } });
fs.writeFileSync("private.pem", privateKey);
fs.writeFileSync("public.pem", publicKey);
```

---

## 2. 解析 asar 布局（禁止硬编码偏移）

asar 结构：`UInt32LE(headerPickleSize)` + header JSON + padding + 文件数据区（按 header 内 offset 顺序紧凑排列）。

```js
const buf = fs.readFileSync(ASAR);
const headerJsonLen = buf.readUInt32LE(4);
const header = JSON.parse(buf.subarray(12, 12 + headerJsonLen).toString("utf8"));

// 数据区起点 = 总长 - 所有文件 size 之和
let sum = 0;
(function walk(n){ for (const m of Object.values(n.files)) m.files ? walk(m) : sum += m.size; })(header);
const dataStart = buf.length - sum;

const node = header.files["launch.dist.js"];
const absOff = dataStart + Number(node.offset);
console.log({ dataStart, absOff, size: node.size, integrity: node.integrity });
```

本样本实测值，用于对表：

| 字段 | 值 |
|---|---|
| 文件总长 | 398826 |
| dataStart | 1060 |
| atom.compiled.dist.jsc | size 379912, offset 0 |
| launch.dist.bak.js | size 1383, offset 379912 |
| launch.dist.js | size 16220, offset 381295 |
| package.json | size 251, offset 397515 |
| launch.dist.js 绝对偏移 | **382355**（= 1060 + 381295） |

**判定标准**：`buf.subarray(absOff, absOff+size)` 必须包含 `require("./atom.compiled.dist.jsc")`。否则偏移算错，停手。

`launch.dist.js` 的 16220 字节就是我们的可用预算：新代码只要不超过它，就能原地覆盖，**不需要重打包整个 asar**（重打包要重建 integrity 表和 padding，风险高得多）。

---

## 3. 阶段一：换公钥 + 绕过自检（改写 launch.dist.js）

替换策略：**保留原 loader 尾部不动**，只在开头插入自己的 hook。具体做法是把 `launch.dist.bak.js`（原始未经修改的 loader，1383 字节，已存在于 asar 内）当作模板，锚点插入：

```js
const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
const newText = bakText.replace(ANCHOR, HOOK + ";" + ANCHOR);
```

`bakText` 从 `_asar_pack\launch.dist.bak.js` 或 asar 内同名文件取。这样 `.jsc` 字节码加载逻辑逐字节不变，不会引入新问题。

### 3.1 必须实现的四件事

**① 文件读取重定向（绕过 [LC] 完整性）**

客户端会读 `app.asar/launch.dist.js` 算 SHA256。让它读到的永远是原始内容：

```js
const RB = fs.readFileSync.bind(fs);
const BAK = RB(path.join(__dirname, "launch.dist.bak.js"));
function isLd(p){ return p != null &&
  path.basename(String(p)).toLowerCase() === "launch.dist.js"; }
function bakRes(o){ const e = typeof o === "string" ? o : (o && o.encoding);
  return e ? BAK.toString(e) : Buffer.from(BAK); }
```
必须同时 patch `fs` 和 `original-fs`，且覆盖三个入口：`readFileSync` / `readFile` / `promises.readFile`。

**② 公钥替换**

```js
const OPD = crypto.publicDecrypt.bind(crypto);
crypto.publicDecrypt = function(key, buf){
  // 先处理 Integrity 密文（见 ③）
  try { return OPD({ key: MY_PUB, padding: 1 }, buf); }
  catch(e){ return OPD(key, buf); }   // 解不开就退回原公钥，避免整体崩
};
```

**③ fn_0212 不透明完整性校验**

客户端内置一段 256 字节密文，用公钥解出后与硬编码明文比对。实测常量：

```js
const INTEG_EXPECTED = "pvyXdYxWo0HsOVIEo4RFsMiWAmuDpJZ4TZeO0g9ecBchHm86UjJZZftJ2QWkuqlFKPWNbI8lkusRKlRT9SPun07e9mhQ1lZeiojs";
const INTEG_HEAD = [168,163,144,221,123,254,219,133,103,114,95,163,156,84,26,17];
```

两处拦截，双保险：

```js
// a) publicDecrypt 命中该密文时，直接返回期望明文
if (Buffer.isBuffer(buf) && buf.length === 256 && buf.subarray(0,16).equals(Buffer.from(INTEG_HEAD)))
  return Buffer.from(INTEG_EXPECTED);

// b) Buffer.prototype.equals 命中该明文时，强制 true
const BE = Buffer.prototype.equals;
Buffer.prototype.equals = function(o){
  if (isInteg(this) || isInteg(o)) return true;
  return BE.call(this, o);
};
```

**④ 捕获 IPC handler（为阶段三的续命做准备）**

```js
const ip = require("electron").ipcMain;
const oh = ip.handle.bind(ip);
ip.handle = function(ch, fn){
  if (String(ch) === "offlineActivation") { OFF = fn; /* 捕获 */ }
  return oh(ch, fn);
};
```

### 3.2 写入与校验

```js
const bytes = Buffer.from(newText, "utf8");
if (bytes.length > LSIZE) throw new Error("超过槽位大小");
new vm.Script(newText);                      // 语法自检，必须通过
const buf = fs.readFileSync(ASAR);
if (!buf.subarray(LOFF, LOFF+LSIZE).toString("utf8").includes(endNeedle)) throw ...
const padded = Buffer.alloc(LSIZE, 0x0a);    // 换行填充，JS 允许尾部空白
bytes.copy(padded, 0); padded.copy(buf, LOFF);
fs.writeFileSync(ASAR, buf);
```

**判定标准**：写回后重新读该区域，头部是 `"use strict"`，尾部仍含 `require("./atom.compiled.dist.jsc")`，中间空白只允许 `\n`。

> 写前务必备份：`Copy-Item app.asar app.asar.bak_before_reinject`

---

## 4. 阶段二：生成激活码

```js
const payload = JSON.stringify({
  email: "attacker@example.com",
  license: "W4Z8D5-PARZG2-7SLDF9-8QMJ9V",
  fingerprint: FP,                        // 1.2 算出的 10 字符
  deviceId: "00000000-0000-0000-0000-000000000000",
  version: "1.13.7",
  date: new Date().toLocaleDateString("en-US")
});
const cipher = crypto.privateEncrypt(
  { key: PRIV, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(payload));
if (cipher.length !== 256) throw new Error("密文必须 256 字节");
const b64 = cipher.toString("base64");     // 344 字符
```

**必须做回环验证**（用公钥解回来，逐字节比对 JSON）：不验证就往下走，等于赌。

### 4.1 UI 入口的正确格式（极易踩）

前端 `LicenseIndex.*.js` 里，主界面（Email / Re-enter Email / 序列号）走的是**联网校验** `Setting.activate()`，把 `+base64` 粘这里必然报「请输入正确的序列号」。

真正吃离线码的是点「离线激活」后的第二阶段的 `Activation Token` 文本框，代码逻辑：

```js
onChange: e => { const t = e.target.value;
  "+" == t[0] && "#" == t[t.length-1] && onOfflineActivation(t); }

// 而 onOfflineActivation 内部第一行：
token = token.substr(1, token.length - 2);   // 砍掉首字符和末字符
```

结论：粘贴内容必须是 **`+` + 344 字符 base64 + `#`**，共 346 字符。
只给 `+base64` 会砍掉末尾的 `=`，密文变 257 字节，`publicDecrypt` 直接失败。

粘完自动提交，不需要点按钮。

---

## 5. 阶段三：应对启动续期（renew）

### 5.1 现象与定位

激活成功、重启后回到未激活。`typora.log` 时序（毫秒级）：

```
178  [L] installDate is ... trail remains: 15 days
221  [watch L] hasL: true          ← 读到并解开了我们的授权
     [renewL]: unfill due to renew fail   ← 300ms 内被清空
506  onUnfillLicense
```

`app.asar` 内相关字符串常量：`[renewLicense] license renewed in 12h`、`[renewL]: unfill due to renew fail`、`Failed to Renew L`、`https://typoraio.cn/store/`、`renew`、`deviceId`、`43200000`。

请求体实测：`{"v":"win|1.13.7","license":"<序列号>","l":"<deviceId>","u":"<uuid>","type":""}`，POST 到 `typoraio.cn/store`。

**已排除的无效方案**（不要重复踩）：

- 把 payload 的 `date` 推到未来（试过 `12/21/2026`）→ 仍然 unfill，续期不是用它判断窗口。
- 在 payload 里加 `type` → 请求体变了，服务器照样拒。
- 断网 / 改 hosts → 任何失败都走同一分支，一样 unfill。

### 5.2 有效方案：启动后自动重新注入

因为 `offlineActivation` 的 handler 我们已捕获（3.1 ④），可以直接在进程内调用它，效果等同于用户手工粘贴一次：

```js
function inject(tag){
  const BW = require("electron").BrowserWindow;
  const ws = BW.getAllWindows().filter(w => !w.isDestroyed());
  const wc = ws.length ? ws[0].webContents : null;
  const ev = { sender: wc || DUMMY, reply(){}, senderFrame: null, ports: [] };
  Promise.resolve(OFF(ev, TOKEN)).then(r => log("inject", tag, r));
}

[300,500,700,900,1200,1600,2400,4000,8000]
  .forEach(t => setTimeout(() => inject(t), t));
```

`TOKEN` 就是第 4 节产出的**裸 base64**（344 字符，不带 `+` / `#`，因为 IPC 层收到的是裁剪后的形式）。

实测时序：`hasL:true` → 200ms 被 unfill → 300ms 注入返回 `[true,"","<email>","<license>"]` → 界面正常。

### 5.3 三条硬性禁忌（踩过，会导致应用直接退出）

1. **绝对不要 `win.close()` 关掉 `License Info` 窗口**。它带 `quitOnClose`，关闭即 `app.quit()`，进程数直接归零。
2. **不要在窗口初始化阶段 `webContents.reload()`**。实测会把进程干掉。
3. 注入时窗口可能还不存在（330ms 前），`BrowserWindow.getAllWindows()` 为空是正常的，用 dummy `sender` 兜住即可，不要因此 return。

---

## 6. 完整脚本骨架

两个文件，放在任意目录，Node 直接跑。

### 6.1 `gen_license.js` —— 生成激活码

```js
const fs = require("fs"), crypto = require("crypto"), { execSync } = require("child_process");
const ROOT = process.argv[2];                       // 样本根目录
const privPem = fs.readFileSync(ROOT + "\\private.pem", "utf8");
const pubPem  = fs.readFileSync(ROOT + "\\public.pem", "utf8");
const der = p => crypto.createPublicKey(p).export({format:"der",type:"spki"}).toString("hex");

// 对表：asar 内嵌公钥必须等于我们的 public.pem，否则后面全白做
const asar = fs.readFileSync(ROOT + "\\Typora\\resources\\app.asar");
const keys = [...asar.toString("latin1")
  .matchAll(/-----BEGIN PUBLIC KEY-----[\s\S]{200,1200}?-----END PUBLIC KEY-----/g)].map(m => m[0]);
console.log("asar 内公钥块数:", keys.length,
            "匹配我们的:", keys.filter(k => der(k) === der(pubPem)).length);

const guid = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
                      {encoding:"utf8"}).match(/MachineGuid\s+REG_SZ\s+(\S+)/i)[1];
const fp = crypto.createHash("sha256").update(guid).update("typora")
                 .digest("base64").slice(0,10).replace(/[/=+-]/g,"a");

const payload = JSON.stringify({ email:"attacker@example.com",
  license:"W4Z8D5-PARZG2-7SLDF9-8QMJ9V", fingerprint:fp,
  deviceId:"00000000-0000-0000-0000-000000000000", version:"1.13.7",
  date: new Date().toLocaleDateString("en-US") });
if (Buffer.byteLength(payload) > 245) throw new Error("明文超长");

const b64 = crypto.privateEncrypt({key:privPem, padding:crypto.constants.RSA_PKCS1_PADDING},
                                  Buffer.from(payload)).toString("base64");
const back = crypto.publicDecrypt({key:pubPem, padding:crypto.constants.RSA_PKCS1_PADDING},
                                  Buffer.from(b64,"base64")).toString("utf8");
if (back !== payload) throw new Error("回环验证失败");

console.log("指纹:", fp);
console.log("UI 粘贴用:", "+" + b64 + "#");   // 346 字符
console.log("注入用裸串:", b64);               // 344 字符
```

### 6.2 `patch_asar.js` —— 植入 hook

```js
const fs = require("fs"), vm = require("vm");
const ROOT = process.argv[2], ASAR = ROOT + "\\Typora\\resources\\app.asar";

// —— 自动解析布局，不硬编码 ——
const buf0 = fs.readFileSync(ASAR);
const headerJsonLen = buf0.readUInt32LE(4);
const header = JSON.parse(buf0.subarray(12, 12+headerJsonLen).toString("utf8"));
let sum = 0; (function w(n){ for (const m of Object.values(n.files)) m.files ? w(m) : sum += m.size; })(header);
const dataStart = buf0.length - sum;
const node = header.files["launch.dist.js"];
const LOFF = dataStart + Number(node.offset), LSIZE = node.size;

const bakText = fs.readFileSync(ROOT + "\\Typora\\_asar_pack\\launch.dist.bak.js", "utf8");
const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
const HOOK = `/* 见第 3 节 + 第 5.2 节，内置 MY_PUB / TOKEN / INTEG_* 常量 */`;
const newText = bakText.replace(ANCHOR, HOOK.trim() + ";" + ANCHOR);
const bytes = Buffer.from(newText, "utf8");
if (bytes.length > LSIZE) throw new Error(`超长 ${bytes.length}/${LSIZE}`);
new vm.Script(newText);

if (!fs.existsSync(ASAR + ".bak_before_reinject")) fs.copyFileSync(ASAR, ASAR + ".bak_before_reinject");
const buf = fs.readFileSync(ASAR);
if (!buf.subarray(LOFF, LOFF+LSIZE).toString("utf8")
        .includes('require("./atom.compiled.dist.jsc")')) throw new Error("偏移校验失败");
const padded = Buffer.alloc(LSIZE, 0x0a); bytes.copy(padded, 0); padded.copy(buf, LOFF);
fs.writeFileSync(ASAR, buf);
console.log("OK", bytes.length + "/" + LSIZE);
```

---

## 7. 验证清单（缺一不可）

| # | 检查项 | 期望 |
|---|---|---|
| 1 | asar 内嵌公钥 DER | 等于自己的 `public.pem` |
| 2 | `private.pem` 与 `public.pem` | 配对成立 |
| 3 | 激活码回环 | 解出的 JSON 与原文逐字节相同 |
| 4 | 密文长度 | 恒为 256 字节 |
| 5 | 明文长度 | ≤ 245 字节 |
| 6 | 指纹 | 与 `hook.log` 中 fn_0211 预测值一致 |
| 7 | asar 写入后 | 区域含 loader 尾部，尾部填充仅 `\n` |
| 8 | 启动后 `hook.log` | 出现 `inject t300 -> [true,...]` |
| 9 | 启动后 `typora.log` | `hasL: true`，且注入项晚于 `unfill` |
| 10 | 进程 | 存活，窗口标题为 `Typora` 而非 `License Info` |

---

## 8. 排错对照表

| 现象 | 根因 | 处理 |
|---|---|---|
| 「请输入正确的序列号」 | 粘在了主界面联网通道 | 改走「离线激活」→ Activation Token |
| `Invalid Activation Token` | 首尾不是 `+`/`#`，或 `window.webkit` 分支被误触发 | 严格 `+…=#`；该分支在 Windows 下不成立 |
| 密文 257 字节 / 解密失败 | 末尾 `=` 被 `substr` 砍掉 | 补 `#` 收尾 |
| 激活成功但重启失效 | renew 失败后 unfill | 上第 5 节注入方案 |
| 启动即退出 | 关了 `License Info` 窗口 / 早期 reload | 删掉这两个动作 |
| 白屏或 loader 报错 | 覆盖破坏了 `.jsc` 加载尾部 | 从 `.bak_before_reinject` 还原 |
| 换机器后失效 | fingerprint 绑定 MachineGuid | 重新跑 6.1 出码 |

---

## 9. 回滚

```powershell
Copy-Item "$ROOT\Typora\resources\app.asar.bak_before_reinject" `
          "$ROOT\Typora\resources\app.asar" -Force
```

回滚后即恢复原始 1.13.7，激活状态同时丢失（原厂验签不认我们的公钥）。

---

## 10. 能力边界（写给下一个执行者）

- 本方案**不修改** `.jsc` 字节码、不重打包 asar、不触碰 exe。所有改动集中在 `launch.dist.js` 的 16220 字节槽位内，属可逆改动。
- 无法消除 renew 请求本身。服务端拒绝伪造 license 是设计使然，客户端只能在失败后补回。因此每次启动存在约 200–300ms 的未授权空窗，肉眼不可见。
- 试用期计数（`installDate + 15 days`）依旧在跑。若某天该窗口期落到注入之前，可能出现到期提示，届时需要把注入时序继续前置，或改用无 renew 的旧版本。
- 任何自动更新都会覆盖 asar 并令全部改动失效。
