"use strict";
/**
 * asar 读写工具（Electron asar v3 格式）。
 *
 * 头部结构（实测）：
 *   [4][outerLen][headerLen][jsonLen][json][padding]
 *    4     4          4         4     jsonLen   0~3
 *
 *   outerLen  = headerLen + 4
 *   headerLen = jsonLen + 4 + padding
 *   padding   = (4 - jsonLen % 4) % 4
 *
 * 数据区紧随头部，各文件按 header 内的 offset 顺序紧凑排列。
 */
const fs = require("fs");

/** 解包为 Map<文件名, {data, integrity?}> */
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

  return { files, dataStart, total: buf.length, header };
}

/** 打包回 Buffer；offset 全部重算 */
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

function readAsar(file) {
  return unpack(fs.readFileSync(file));
}

/** 写回；首次写入前自动留一份 .orig 备份 */
function writeAsar(file, files) {
  const out = pack(files);
  const backup = file + ".orig";
  if (fs.existsSync(file) && !fs.existsSync(backup)) fs.copyFileSync(file, backup);
  fs.writeFileSync(file, out);
  return { out, backup };
}

/** 原地覆盖指定文件的槽位（不重排其他文件），返回是否成功 */
function overwriteSlot(origBuf, name, newData) {
  const { files, dataStart } = unpack(origBuf);
  const entry = files.get(name);
  if (!entry) throw new Error("asar 内没有 " + name);
  if (newData.length > entry.data.length) return false;

  const jsonLen = origBuf.readUInt32LE(12);
  const pad = (4 - (jsonLen % 4)) % 4;
  const header = JSON.parse(origBuf.subarray(16, 16 + jsonLen).toString("utf8"));
  const off = dataStart + Number(header.files[name].offset);

  const padded = Buffer.alloc(entry.data.length, 0x0a);
  newData.copy(padded, 0);
  padded.copy(origBuf, off);
  return true;
}

module.exports = { unpack, pack, readAsar, writeAsar, overwriteSlot };
