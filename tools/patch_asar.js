#!/usr/bin/env node
"use strict";
/**
 * 改写 Typora app.asar 内的 launch.dist.js（换公钥 + 绕过完整性自检 + 自动激活）。
 *
 * 用法: node tools/patch_asar.js <样本根目录> [--repack]
 * 根目录下需有: Typora/resources/app.asar, private.pem, public.pem
 *
 * 两种写入策略，自动选择：
 *   1. 槽位够大 → 原地覆盖（保守，不动其他文件）
 *   2. 槽位不够 → 整个 asar 解包后重打包（原厂 asar 的 launch.dist.js 只有 1383 字节，
 *      装不下 hook，必须走这条）
 *
 * 原理见 docs/REVERSE_HANDBOOK.md
 */
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const ROOT = process.argv[2];
if (!ROOT) {
  console.error("用法: node tools/patch_asar.js <样本根目录> [--repack]");
  process.exit(1);
}

const ASAR = path.join(ROOT, "Typora", "resources", "app.asar");
const PRIV = fs.readFileSync(path.join(ROOT, "private.pem"), "utf8").trim();
const PUB = fs.readFileSync(path.join(ROOT, "public.pem"), "utf8").trim();

const INTEG_EXPECTED =
  "pvyXdYxWo0HsOVIEo4RFsMiWAmuDpJZ4TZeO0g9ecBchHm86UjJZZftJ2QWkuqlFKPWNbI8lkusRKlRT9SPun07e9mhQ1lZeiojs";
const INTEG_HEAD = [168, 163, 144, 221, 123, 254, 219, 133, 103, 114, 95, 163, 156, 84, 26, 17];

/* ---------------- asar 读写 ---------------- */

/** 头部结构: [4][outerLen][headerLen][jsonLen][json][padding] */
function unpack(buf) {
  const jsonLen = buf.readUInt32LE(12);
  const pad = (4 - (jsonLen % 4)) % 4;
  const dataStart = 16 + jsonLen + pad;
  const header = JSON.parse(buf.subarray(16, 16 + jsonLen).toString("utf8"));

  const files = new Map();
  (function walk(node, prefix) {
    for (const [name, meta] of Object.entries(node.files || {})) {
      const p = prefix ? prefix + "/" + name : name;
      if (meta.files) {
        walk(meta, p);
      } else {
        const start = dataStart + Number(meta.offset);
        files.set(p, {
          data: Buffer.from(buf.subarray(start, start + meta.size)),
          integrity: meta.integrity,
        });
      }
    }
  })(header, "");

  return { files, dataStart, total: buf.length };
}

function pack(files) {
  let offset = 0;
  const headerFiles = {};
  const chunks = [];
  for (const [name, f] of files) {
    const entry = { size: f.data.length, offset: String(offset) };
    if (f.integrity) entry.integrity = f.integrity;
    headerFiles[name] = entry;
    chunks.push(f.data);
    offset += f.data.length;
  }

  const jsonBuf = Buffer.from(JSON.stringify({ files: headerFiles }), "utf8");
  const pad = (4 - (jsonBuf.length % 4)) % 4;

  const headerBuf = Buffer.alloc(4 + jsonBuf.length + pad);
  headerBuf.writeUInt32LE(jsonBuf.length, 0);
  jsonBuf.copy(headerBuf, 4);

  const outer = Buffer.alloc(4 + headerBuf.length);
  outer.writeUInt32LE(headerBuf.length, 0);
  headerBuf.copy(outer, 4);

  const sizeBuf = Buffer.alloc(8);
  sizeBuf.writeUInt32LE(4, 0);
  sizeBuf.writeUInt32LE(outer.length, 4);

  return Buffer.concat([sizeBuf, outer, ...chunks]);
}

/* ---------------- hook ---------------- */

const HOOK = `
(function(){
var crypto=require("crypto"),cp=require("child_process");
var lp=path.join(path.dirname(process.execPath),"hook.log");
function L(){var a=[].slice.call(arguments).map(function(x){try{return typeof x==="string"?x:JSON.stringify(x)}catch(e){return String(x)}});try{fs.appendFileSync(lp,"["+new Date().toISOString()+"] [h] "+a.join(" ")+"\\n")}catch(e){}}
var RB=fs.readFileSync.bind(fs);
var BAK=RB(path.join(__dirname,"launch.dist.bak.js"));
function isLd(p){return p!=null&&path.basename(String(p)).toLowerCase()==="launch.dist.js"}
function bakRes(o){var e=null;if(typeof o==="string")e=o;else if(o&&o.encoding)e=o.encoding;return e?BAK.toString(e):Buffer.from(BAK)}
function patchFs(m){if(!m)return;
if(typeof m.readFileSync==="function"){var o1=m.readFileSync.bind(m);m.readFileSync=function(f,op){if(isLd(f))return bakRes(op);return o1(f,op)}}
if(typeof m.readFile==="function"){var o2=m.readFile.bind(m);m.readFile=function(f,op,cb){if(typeof op==="function"){cb=op;op=undefined}if(isLd(f)){var d=bakRes(op);if(typeof cb==="function"){process.nextTick(function(){cb(null,d)});return}return Promise.resolve(d)}return o2(f,op,cb)}}
if(m.promises&&typeof m.promises.readFile==="function"){var o3=m.promises.readFile.bind(m.promises);m.promises.readFile=function(f,op){if(isLd(f))return Promise.resolve(bakRes(op));return o3(f,op)}}}
patchFs(fs);
try{patchFs(require("original-fs"))}catch(e){}
var PRIV=${JSON.stringify(PRIV)};
var PUB=${JSON.stringify(PUB)};
var IE=Buffer.from(${JSON.stringify(INTEG_EXPECTED)},"utf8");
var IH=Buffer.from(${JSON.stringify(INTEG_HEAD)});
var OPD=crypto.publicDecrypt.bind(crypto);
crypto.publicDecrypt=function(key,buf){
try{if(Buffer.isBuffer(buf)&&buf.length===256&&buf.subarray(0,16).equals(IH))return Buffer.from(IE)}catch(e){}
var r;
try{r=OPD({key:PUB,padding:crypto.constants.RSA_PKCS1_PADDING},buf)}catch(e){try{return OPD(key,buf)}catch(e2){throw e2}}
try{var t=r.toString("utf8"),o=JSON.parse(t);if(o&&o.fingerprint){r.email=o.email;r.license=o.license;r.fingerprint=o.fingerprint;r.deviceId=o.deviceId}}catch(e){}
return r};
var BE=Buffer.prototype.equals;
var isIE=function(b){return Buffer.isBuffer(b)&&b.length===IE.length&&b.toString("latin1")===IE.toString("latin1")};
Buffer.prototype.equals=function(o){try{if(isIE(this)||isIE(o))return true}catch(e){}return BE.call(this,o)};
function machineGuid(){
try{var out=cp.execSync('reg query "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Cryptography" /v MachineGuid',{encoding:"utf8",windowsHide:true});var m=out.match(/MachineGuid\\s+REG_SZ\\s+(\\S+)/i);if(m)return m[1].trim()}catch(e){L("guid fail",e.message)}
return null}
function buildToken(){
var guid=machineGuid();if(!guid)return null;
var fp=crypto.createHash("sha256").update(guid).update("typora").digest("base64").slice(0,10).replace(/[/=+-]/g,"a");
var ver="1.13.7";try{ver=require("./package.json").version||ver}catch(e){}
var payload=JSON.stringify({email:"typora@local",license:"W4Z8D5-PARZG2-7SLDF9-8QMJ9V",fingerprint:fp,deviceId:"00000000-0000-0000-0000-000000000000",version:ver,date:new Date().toLocaleDateString("en-US")});
var b=Buffer.from(payload,"utf8");if(b.length>245){L("payload too long",b.length);return null}
try{return crypto.privateEncrypt({key:PRIV,padding:crypto.constants.RSA_PKCS1_PADDING},b).toString("base64")}catch(e){L("sign fail",e.message);return null}}
var OFF=null;
(function(){var el;try{el=require("electron")}catch(e){return}var ip=el.ipcMain;if(!ip||ip.__hk||typeof ip.handle!=="function")return;
var oh=ip.handle.bind(ip);
ip.handle=function(ch,fn){if(String(ch)==="offlineActivation"){OFF=fn}return oh(ch,fn)};
ip.__hk=1})();
function inject(tag){
if(!OFF)return;
var el;try{el=require("electron")}catch(e){return}
var BW=el.BrowserWindow,wc=null;
if(BW){var ws=BW.getAllWindows().filter(function(w){return !w.isDestroyed()});if(ws.length)wc=ws[0].webContents}
var tok=buildToken();if(!tok){L("skip "+tag+": no token");return}
var ev={sender:wc||{send:function(){},isDestroyed:function(){return false}},reply:function(){},senderFrame:null,ports:[]};
try{Promise.resolve(OFF(ev,tok)).then(function(r){L("activate "+tag+" ->",JSON.stringify(r))}).catch(function(e){L("activate "+tag+" err",e&&e.message)})}catch(e){L("activate "+tag+" throw",e&&e.message)}}
[300,700,1200,2000,3500,6000,10000].forEach(function(t){setTimeout(function(){inject("t"+t)},t)});
})();
`;

/* ---------------- 主流程 ---------------- */

const buf0 = fs.readFileSync(ASAR);
const { files } = unpack(buf0);

// 原始 loader：改过的包里有独立备份，原厂包里 launch.dist.js 本身就是原始 loader
const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
let loaderName = null;
for (const [name, f] of files) {
  if (!/launch\.dist\.(bak\.js|js)$/.test(name)) continue;
  if (f.data.toString("utf8").includes(ANCHOR)) {
    loaderName = name;
    break;
  }
}
if (!loaderName) throw new Error("asar 内未找到含 v8 flags 的原始 loader");
const loaderText = files.get(loaderName).data.toString("utf8");
console.log("loader 来源:", loaderName, "(" + loaderText.length + " bytes)");

const newText = loaderText.replace(ANCHOR, HOOK.trim() + ";" + ANCHOR);
const bytes = Buffer.from(newText, "utf8");
new vm.Script(newText);
console.log("新 launch.dist.js:", bytes.length, "bytes, syntax PASS");

const current = files.get("launch.dist.js");
if (!current) throw new Error("asar 内没有 launch.dist.js");
const slot = current.data.length;
console.log("原槽位:", slot, "bytes");

const forceRepack = process.argv.includes("--repack");
const useRepack = forceRepack || bytes.length > slot;
console.log("写入策略:", useRepack ? "重打包整个 asar" : "原地覆盖槽位");

// 原始 loader 需要作为备份留在包内（hook 靠它绕过自检）
if (!files.has("launch.dist.bak.js")) {
  files.set("launch.dist.bak.js", { data: Buffer.from(loaderText, "utf8") });
  console.log("补充 launch.dist.bak.js（原始 loader 备份）");
}

// 内容变了，旧的 integrity 哈希必然失配；去掉该字段让 Electron 跳过校验
files.set("launch.dist.js", { data: bytes });

const backup = ASAR + ".orig";
if (!fs.existsSync(backup)) fs.copyFileSync(ASAR, backup);

let out;
if (useRepack) {
  out = pack(files);
} else {
  out = Buffer.from(buf0);
  // 原地覆盖时需要按原 offset 定位
  const jsonLen = buf0.readUInt32LE(12);
  const pad = (4 - (jsonLen % 4)) % 4;
  const dataStart = 16 + jsonLen + pad;
  const json = JSON.parse(buf0.subarray(16, 16 + jsonLen).toString("utf8"));
  const off = dataStart + Number(json.files["launch.dist.js"].offset);
  const padded = Buffer.alloc(slot, 0x0a);
  bytes.copy(padded, 0);
  padded.copy(out, off);
}

fs.writeFileSync(ASAR, out);

// 自检：重新解包，确认结构与内容
const verify = unpack(fs.readFileSync(ASAR));
const ld = verify.files.get("launch.dist.js");
const okMain = ld && ld.data.toString("utf8").includes('require("./atom.compiled.dist.jsc")');
const okBak = verify.files.has("launch.dist.bak.js");
const jsc = verify.files.get("atom.compiled.dist.jsc");
console.log("自检 文件数:", verify.files.size, "| loader 尾部:", okMain, "| bak 存在:", okBak, "| jsc 完整:", !!jsc && jsc.data.length === 379912);
console.log("asar 大小:", out.length, "原:", buf0.length);
console.log("备份:", backup);
