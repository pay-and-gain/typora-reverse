# Typora 1.13.7 离线激活逆向

对 Typora 1.13.7（Windows）授权链的完整分析、复现与持久化方案。

> 仅用于本地研究与兼容性验证。请在你持有合法授权的设备上使用。

---

## 一句话结论

客户端校验授权时只做 `crypto.publicDecrypt(内置公钥, 授权密文)` 并把结果当 JSON 用，**全程不联网复核签名**。因此把内置公钥换成自己生成的公钥、再用配对私钥签发授权，客户端就永远验得过。这是换锁芯，不是配钥匙。

## 成品

Releases 里的 `Typora-1.13.7-portable.zip` 是开箱即用的便携包：解压、双击 `Typora.exe`，约 1 秒内自动完成授权，不需要填写任何序列号。

它内置的是**运行时签名**：每次启动读取本机 `MachineGuid`、算出指纹、当场签一份授权提交。所以换电脑也能直接用，无需重新配置。

## 目录

```
docs/REVERSE_HANDBOOK.md   完整逆向手册（偏移、常量、时序、排错表）
tools/patch_asar.js        改写 app.asar 内 launch.dist.js（换公钥 + 绕过自检 + 自动注入）
tools/gen_license.js       生成单机激活码（手工粘贴用）
```

## 自行构建

前置：Node.js、一份 Typora 1.13.7 安装目录。

```bash
# 1. 生成自己的密钥对，放在样本根目录
node -e "const c=require('crypto'),f=require('fs');const{publicKey,privateKey}=c.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});f.writeFileSync('private.pem',privateKey);f.writeFileSync('public.pem',publicKey)"

# 2. 改写 app.asar（自动解析布局，不写死偏移）
node tools/patch_asar.js <样本根目录>

# 3. 可选：生成一次性激活码
node tools/gen_license.js <样本根目录>
```

样本根目录下应包含 `Typora/resources/app.asar`、`private.pem`、`public.pem`。

手工激活时注意 UI 入口：**不是**主界面的「序列号」框（那走联网校验），而是点「离线激活」后的 `Activation Token` 输入框，内容格式为 `+<base64>#`——首尾各一个字符会被 `substr(1, len-2)` 裁掉，末尾的 `#` 是必需的，否则 base64 的 `=` 会被吃掉。

## 实现要点

1. **换公钥**：包装 `crypto.publicDecrypt`，把 key 参数替换为自己的 PEM，解不开时回退原公钥。
2. **绕过完整性自检**：客户端会 SHA256 校验 `launch.dist.js` 自身，并解密一段硬编码密文比对明文。前者用 `fs.readFileSync` 重定向返回原始备份内容，后者在 `publicDecrypt` 与 `Buffer.prototype.equals` 两处短路。
3. **原地改写**：`launch.dist.js` 在 asar 内有固定槽位（本样本 16220 字节），新代码不超过槽位即可直接覆盖，不需要重打包整个 asar。原 loader 尾部从 `launch.dist.bak.js` 原样拼接，保证 `.jsc` 字节码加载逻辑逐字节不变。
4. **应对续期**：客户端每次启动会向 `typoraio.cn/store` 提交续期请求，服务器拒绝后就清空本地授权。这是服务端行为，无法从客户端根除，只能在其后自动补回——hook 捕获 `offlineActivation` 的 IPC handler，在启动后 300ms 起多次重新提交。

## 已知限制

- **续期清空**：每次启动存在约 200–300ms 的未授权空窗，肉眼不可见，但确实存在。
- **试用期计数**：`installDate + 15 days` 仍在跑，长期使用需要观察。
- **更新会覆盖**：任何版本升级都会替换 `app.asar`，全部改动失效。请关闭自动更新。
- **指纹绑定**：手工激活码与本机 `MachineGuid` 绑定；成品包采用运行时签名，不受此限。

## 免责

本项目仅记录对客户端授权机制的技术分析。使用者应自行确保对所用软件拥有合法授权，并遵守当地法律法规与软件许可协议。作者不对任何使用后果负责。
