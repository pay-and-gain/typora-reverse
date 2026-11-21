#!/usr/bin/env node
"use strict";
/**
 * 解析 asar 布局：列出文件表，反推数据区起点，校验目标槽位。
 *
 * 用法: node tools/probes/probe_layout.js <app.asar 路径>
 */
const fs = require("fs");

const ASAR = process.argv[2];
if (!ASAR) {
  console.error("用法: node tools/probes/probe_layout.js <app.asar>");
  process.exit(1);
}

const buf = fs.readFileSync(ASAR);
const head = buf.subarray(0, 8192).toString("latin1");

// 各文件 size 之和，总长减去它即为数据区起点（asar 数据区紧凑排列）
let sum = 0;
for (const m of head.matchAll(/"size":(\d+)/g)) sum += Number(m[1]);
const dataStart = buf.length - sum;

console.log("file bytes :", buf.length);
console.log("header head:", JSON.stringify(head.slice(0, 80)));
console.log("dataStart  :", dataStart);
console.log("");

// 逐个条目打印，便于对照
const entryRe = /"([^"]+)":\{"size":(\d+),"offset":"?(\d+)"?/g;
let m;
while ((m = entryRe.exec(head)) !== null) {
  const [, name, size, offset] = m;
  const abs = dataStart + Number(offset);
  console.log(
    name.padEnd(28),
    "size=" + String(size).padEnd(8),
    "off=" + String(offset).padEnd(8),
    "abs=" + abs
  );
}

// 槽位可覆盖性检查
const target = head.match(/"launch\.dist\.js":\{"size":(\d+),"offset":"?(\d+)"?/);
if (target) {
  const size = Number(target[1]);
  const off = dataStart + Number(target[2]);
  const region = buf.subarray(off, off + size).toString("utf8");
  console.log("");
  console.log("launch.dist.js 槽位:", size, "字节 @", off);
  console.log("含 jsc 加载语句:", region.includes('require("./atom.compiled.dist.jsc")'));
}
