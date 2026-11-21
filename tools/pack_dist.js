#!/usr/bin/env node
"use strict";
/**
 * 生成「任意机器启动即自动激活」的分发包改写版。
 *
 * 用法: node tools/pack_dist.js <样本根目录> [--force]
 * 根目录下需有: Typora/resources/app.asar, private.pem, public.pem
 *
 * 与 patch_asar.js 的区别：
 *   patch_asar.js  只换公钥，私钥不进门，激活码由使用者自己粘贴
 *   pack_dist.js   内嵌私钥，每次启动读取本机 MachineGuid、现签授权再注入
 *                  换来的便利是「换电脑免配置」，代价是私钥随包分发
 *
 * 原理见 docs/REVERSE_HANDBOOK.md
 */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { readAsar, pack, overwriteSlot } = require("./lib/asar");

const ROOT = process.argv[2];
if (!ROOT) {
  console.error("用法: node tools/pack_dist.js <样本根目录> [--force]");
  process.exit(1);
}

const ASAR = path.join(ROOT, "Typora", "resources", "app.asar");
const PRIV = fs.readFileSync(path.join(ROOT, "private.pem"), "utf8").trim();
const PUB = fs.readFileSync(path.join(ROOT, "public.pem"), "utf8").trim();

const EXPECTED_VERSION = "1.13.7";
const INTEG_EXPECTED =
  "pvyXdYxWo0HsOVIEo4RFsMiWAmuDpJZ4TZeO0g9ecBchHm86UjJZZftJ2QWkuqlFKPWNbI8lkusRKlRT9SPun07e9mhQ1lZeiojs";
const INTEG_HEAD = [168, 163, 144, 221, 123, 254, 219, 133, 103, 114, 95, 163, 156, 84, 26, 17];

(function assertVersion() {
  let ver = null;
  try {
    ver = JSON.parse(
      fs.readFileSync(path.join(ROOT, "Typora", "resources", "package.json"), "utf8")
    ).version;
  } catch (e) {
    /* 读不到按未知处理 */
  }
  console.log("样本版本:", ver || "(未知)");
  if (ver === EXPECTED_VERSION) return;
  console.warn("[!] INTEG_* 常量与 loader 锚点仅在 " + EXPECTED_VERSION + " 上验证过。");
  if (!process.argv.includes("--force")) {
    console.error("    确认要继续请追加 --force");
    process.exit(3);
  }
})();

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

const buf0 = fs.readFileSync(ASAR);
const { files } = readAsar(ASAR);
console.log("asar 文件数:", files.size, " 大小:", buf0.length);

const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
let loaderName = null;
for (const name of files.keys()) {
  if (!/launch\.dist\.(bak\.js|js)$/.test(name)) continue;
  if (files.get(name).data.toString("utf8").includes(ANCHOR)) {
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

const useRepack = bytes.length > slot;
console.log("写入策略:", useRepack ? "重打包整个 asar" : "原地覆盖槽位");

if (!files.has("launch.dist.bak.js")) {
  files.set("launch.dist.bak.js", { data: Buffer.from(loaderText, "utf8") });
  console.log("补充 launch.dist.bak.js（原始 loader 备份）");
}

files.set("launch.dist.js", { data: bytes });

const backup = ASAR + ".orig";
if (useRepack) {
  const out = pack(files);
  if (!fs.existsSync(backup)) fs.copyFileSync(ASAR, backup);
  fs.writeFileSync(ASAR, out);
  console.log("重打包后大小:", out.length);
} else {
  const out = Buffer.from(buf0);
  overwriteSlot(out, "launch.dist.js", bytes);
  if (!fs.existsSync(backup)) fs.copyFileSync(ASAR, backup);
  fs.writeFileSync(ASAR, out);
}

const verify = readAsar(ASAR);
const ld = verify.files.get("launch.dist.js");
const okMain = ld && ld.data.toString("utf8").includes('require("./atom.compiled.dist.jsc")');
const jsc = verify.files.get("atom.compiled.dist.jsc");
console.log(
  "自检 文件数:", verify.files.size,
  "| loader 尾部:", okMain,
  "| bak 存在:", verify.files.has("launch.dist.bak.js"),
  "| jsc 完整:", !!jsc && jsc.data.length === 379912
);
console.log("asar 大小:", fs.statSync(ASAR).size, " 原:", buf0.length);
