#!/usr/bin/env node
"use strict";
/**
 * 从 minified bundle（单行大文件）里按关键词切出上下文，用来读前端逻辑。
 *
 * 用法: node tools/probes/probe_bundle.js <bundle.js> <关键词> [前后字符数]
 * 例:  node tools/probes/probe_bundle.js LicenseIndex.js "Offline Activation" 900
 */
const fs = require("fs");

const [, , file, ...rest] = process.argv;
if (!file || rest.length === 0) {
  console.error("用法: node tools/probes/probe_bundle.js <bundle.js> <关键词> [前后字符数]");
  process.exit(1);
}

let span = 600;
const needles = [];
for (const a of rest) {
  if (/^\d+$/.test(a)) span = Number(a);
  else needles.push(a);
}

const js = fs.readFileSync(file, "utf8");
console.log("bundle bytes:", js.length);

for (const n of needles) {
  const idx = [];
  let i = -1;
  while ((i = js.indexOf(n, i + 1)) !== -1) idx.push(i);
  console.log("\n########## " + n + " @ " + (idx.join(",") || "未命中") + " ##########");
  for (const p of idx.slice(0, 4)) {
    const seg = js.slice(Math.max(0, p - span), p + span).replace(/\s+/g, " ");
    console.log("--- @" + p + " ---\n" + seg);
  }
}
