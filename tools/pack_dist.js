#!/usr/bin/env node
"use strict";
/**
 * 把「运行时签名」能力的 hook 植入 app.asar，产出可分发包。
 *
 * 用法: node tools/pack_dist.js <样本根目录>
 * 根目录下需有: Typora/resources/app.asar, private.pem, public.pem
 *
 * 与 patch_asar.js 的区别：本脚本生成的 hook 每次启动读取本机 MachineGuid、
 * 现签一份授权再注入，因此同一个包在任何机器上都能自动激活。
 * 代价是私钥随包分发，接收者可提取后签发任意授权。
 */
const fs = require("fs");
const vm = require("vm");
const path = require("path");

const ROOT = process.argv[2];
if (!ROOT) {
  console.error("用法: node tools/pack_dist.js <样本根目录>");
  process.exit(1);
}

const ASAR = path.join(ROOT, "Typora", "resources", "app.asar");
const PRIV = fs.readFileSync(path.join(ROOT, "private.pem"), "utf8").trim();
const PUB = fs.readFileSync(path.join(ROOT, "public.pem"), "utf8").trim();

const INTEG_EXPECTED =
  "pvyXdYxWo0HsOVIEo4RFsMiWAmuDpJZ4TZeO0g9ecBchHm86UjJZZftJ2QWkuqlFKPWNbI8lkusRKlRT9SPun07e9mhQ1lZeiojs";
const INTEG_HEAD = [168, 163, 144, 221, 123, 254, 219, 133, 103, 114, 95, 163, 156, 84, 26, 17];

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

function readEntry(buf, name) {
  const head = buf.subarray(0, 8192).toString("latin1");
  let sum = 0;
  for (const m of head.matchAll(/"size":(\d+)/g)) sum += Number(m[1]);
  const dataStart = buf.length - sum;
  const re = new RegExp(
    '"' + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '":\\{"size":(\\d+),"offset":"?(\\d+)"?'
  );
  const m = head.match(re);
  if (!m) throw new Error("asar 内未找到条目: " + name);
  const size = Number(m[1]);
  return { data: buf.subarray(dataStart + Number(m[2]), dataStart + Number(m[2]) + size), size, off: dataStart + Number(m[2]) };
}

const buf0 = fs.readFileSync(ASAR);
const bak = readEntry(buf0, "launch.dist.bak.js");
const ld = readEntry(buf0, "launch.dist.js");
console.log("bak:", bak.size, "@", bak.off, " ld:", ld.size, "@", ld.off);

const bakText = bak.data.toString("utf8");
const ANCHOR = 'v8.setFlagsFromString("--no-lazy")';
if (!bakText.includes(ANCHOR)) throw new Error("原始 loader 中未找到锚点");

const newText = bakText.replace(ANCHOR, HOOK.trim() + ";" + ANCHOR);
const bytes = Buffer.from(newText, "utf8");
console.log("new:", bytes.length, "/", ld.size);
if (bytes.length > ld.size) throw new Error("超出槽位");

new vm.Script(newText);
console.log("syntax: PASS");

const buf = Buffer.from(buf0);
const padded = Buffer.alloc(ld.size, 0x0a);
bytes.copy(padded, 0);
padded.copy(buf, ld.off);

if (!fs.existsSync(ASAR + ".orig")) fs.copyFileSync(ASAR, ASAR + ".orig");
fs.writeFileSync(ASAR, buf);

const check = fs.readFileSync(ASAR).subarray(ld.off, ld.off + ld.size).toString("utf8");
console.log("written:", check.includes('require("./atom.compiled.dist.jsc")') ? "PASS" : "FAIL");
