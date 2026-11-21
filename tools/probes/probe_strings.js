#!/usr/bin/env node
"use strict";
/**
 * 在二进制（.jsc 字节码 / asar）里按关键词提取相邻的可打印字符串，
 * 用来从 V8 字节码的常量池里还原逻辑线索（日志文案、URL、字段名等）。
 *
 * 用法: node tools/probes/probe_strings.js <二进制文件> <关键词> [前后字节数]
 * 例:  node tools/probes/probe_strings.js app.asar "unfill due to renew" 3000
 */
const fs = require("fs");

const [, , file, needle, ...rest] = process.argv;
if (!file || !needle) {
  console.error("用法: node tools/probes/probe_strings.js <二进制文件> <关键词> [前后字节数]");
  process.exit(1);
}
const span = Number(rest[0] || 2000);

const buf = fs.readFileSync(file);
const text = buf.toString("latin1");

const hits = [];
let i = -1;
while ((i = text.indexOf(needle, i + 1)) !== -1) hits.push(i);

console.log("file bytes:", buf.length, " 命中:", hits.length, " @", hits.join(",") || "-");
if (hits.length === 0) process.exit(0);

// 取第一处命中附近的区域，抽出所有长度 ≥4 的可打印串
const p = hits[0];
const seg = buf.subarray(Math.max(0, p - span), p + span).toString("latin1");
const runs = seg.match(/[\x20-\x7e]{4,}/g) || [];
console.log("\n--- 附近字符串（按出现顺序） ---");
console.log(runs.join("\n"));
