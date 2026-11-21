#!/usr/bin/env node
"use strict";
/**
 * 为当前机器生成一枚 Typora 1.13.7 离线激活码。
 *
 * 用法: node tools/gen_license.js <样本根目录>
 * 根目录下需有: private.pem, public.pem, Typora/resources/app.asar
 *
 * 输出两种形态:
 *   1. UI 粘贴用: "+<base64>#"   —— 点「离线激活」后填进 Activation Token 框
 *   2. 程序注入用: "<base64>"     —— offlineActivation IPC 收到的裸串
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");

const ROOT = process.argv[2];
if (!ROOT) {
  console.error("用法: node tools/gen_license.js <样本根目录>");
  process.exit(1);
}

const privPem = fs.readFileSync(path.join(ROOT, "private.pem"), "utf8");
const pubPem = fs.readFileSync(path.join(ROOT, "public.pem"), "utf8");

const der = (pem) =>
  crypto.createPublicKey(pem).export({ format: "der", type: "spki" }).toString("hex");

// 校验 asar 内嵌公钥确实已被替换
const asar = fs.readFileSync(path.join(ROOT, "Typora", "resources", "app.asar"));
const embedded = [
  ...asar
    .toString("latin1")
    .matchAll(/-----BEGIN PUBLIC KEY-----[\s\S]{200,1200}?-----END PUBLIC KEY-----/g),
].map((m) => m[0]);
const matched = embedded.filter((k) => {
  try {
    return der(k) === der(pubPem);
  } catch {
    return false;
  }
});
console.log("[1] asar 内公钥块:", embedded.length, " 匹配自己的:", matched.length);
if (matched.length === 0) {
  console.error("[!] asar 里的公钥不是你的，先跑 tools/patch_asar.js");
  process.exit(2);
}

// 指纹 = sha256(MachineGuid + "typora").base64.slice(0,10).replace(/[/=+-]/g,"a")
const guid = execSync(
  'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
  { encoding: "utf8" }
).match(/MachineGuid\s+REG_SZ\s+(\S+)/i)[1];
const fp = crypto
  .createHash("sha256")
  .update(guid)
  .update("typora")
  .digest("base64")
  .slice(0, 10)
  .replace(/[/=+-]/g, "a");
console.log("[2] MachineGuid:", guid);
console.log("[2] fingerprint:", fp);

const payload = JSON.stringify({
  email: "typora@local",
  license: "W4Z8D5-PARZG2-7SLDF9-8QMJ9V",
  fingerprint: fp,
  deviceId: "00000000-0000-0000-0000-000000000000",
  version: "1.13.7",
  date: new Date().toLocaleDateString("en-US"),
});
const plain = Buffer.from(payload, "utf8");
if (plain.length > 245) throw new Error("明文超过 245 字节: " + plain.length);
console.log("[3] payload:", plain.length, "bytes");

const cipher = crypto.privateEncrypt(
  { key: privPem, padding: crypto.constants.RSA_PKCS1_PADDING },
  plain
);
if (cipher.length !== 256) throw new Error("密文必须 256 字节");
const b64 = cipher.toString("base64");

// 回环验证：用公钥解回来必须逐字节相同
const back = crypto
  .publicDecrypt({ key: pubPem, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(b64, "base64"))
  .toString("utf8");
if (back !== payload) throw new Error("回环验证失败");
console.log("[4] 回环验证: PASS");
console.log("");
console.log("UI 粘贴用（含首尾包裹，共 " + (b64.length + 2) + " 字符）:");
console.log("+" + b64 + "#");
console.log("");
console.log("程序注入用（裸 base64，共 " + b64.length + " 字符）:");
console.log(b64);
