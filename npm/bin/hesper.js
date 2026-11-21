#!/usr/bin/env node
// npx wrapper for the Hesper binary (M5-2): resolves the platform asset of
// a GitHub release, caches it, and execs it with argv passthrough.
// The engine is a single static Go binary — this wrapper downloads, never
// builds.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const REPO = 'JimMir45/hesper';
const VERSION = process.env.HESPER_VERSION || 'latest'; // or a release tag

function platformAsset() {
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  if (process.platform === 'win32') return `hesper-windows-${arch}.exe`;
  if (process.platform === 'darwin') return `hesper-darwin-${arch}`;
  return `hesper-linux-${arch}`;
}

function cacheDir() {
  return path.join(os.homedir(), '.cache', 'hesper');
}

function download(url, dest, cb) {
  const https = require('https');
  const file = fs.createWriteStream(dest);
  https
    .get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, dest, cb);
      }
      if (res.statusCode !== 200) {
        return cb(new Error(`download ${url}: HTTP ${res.statusCode}`));
      }
      res.pipe(file);
      file.on('finish', () => file.close(cb));
    })
    .on('error', cb);
}

function ensureBinary(cb) {
  const asset = platformAsset();
  const dest = path.join(cacheDir(), VERSION, asset);
  if (fs.existsSync(dest)) {
    try {
      fs.chmodSync(dest, 0o755);
    } catch (_) { /* best effort on win32 */ }
    return cb(null, dest);
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const url = `https://github.com/${REPO}/releases/download/${VERSION}/${asset}`;
  process.stderr.write(`hesper: fetching ${asset} (${VERSION})…\n`);
  download(url, dest, (err) => {
    if (err) {
      try { fs.unlinkSync(dest); } catch (_) { /* keep dir */ }
      return cb(err);
    }
    fs.chmodSync(dest, 0o755);
    cb(null, dest);
  });
}

ensureBinary((err, bin) => {
  if (err) {
    process.stderr.write(`hesper: ${err.message}\n(no release asset yet? build from source: go build ./cmd/hesper)\n`);
    process.exit(1);
  }
  const child = execFile(bin, process.argv.slice(2), { stdio: 'inherit' });
  child.on('error', (e) => {
    process.stderr.write(`hesper: ${e.message}\n`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code === null ? 1 : code);
  });
});
