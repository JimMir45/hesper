#!/usr/bin/env node
// npx wrapper for the Hesper binary (M5-2/M5-4): resolves the release tag,
// downloads the platform asset (naming contract: hesper_<version>_<os>_<arch>[.exe]),
// caches it, and execs it with argv passthrough. The engine is a single
// static Go binary — this wrapper only downloads, never builds.
'use strict';

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const REPO = 'JimMir45/hesper';
// Pin a version: HESPER_VERSION=v0.1.0 (tag form; 'latest' resolves via API).
const WANTED = process.env.HESPER_VERSION || 'latest';

// Asset naming contract — must stay in lockstep with .github/workflows/release.yml.
function platformAsset(version) {
  const goos = process.platform === 'win32' ? 'windows'
    : process.platform === 'linux' ? 'linux'
    : null;
  if (!goos) {
    throw new Error(`no official binary for ${process.platform}/${process.arch} — build from source: go build ./cmd/hesper`);
  }
  const goarch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  return `hesper_${version}_${goos}_${goarch}${goos === 'windows' ? '.exe' : ''}`;
}

function fetch(url, cb) {
  https
    .get(url, { headers: { 'user-agent': 'hesper-npm-wrapper' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return fetch(res.headers.location, cb);
      }
      cb(null, res);
    })
    .on('error', cb);
}

function resolveVersion(cb) {
  if (WANTED !== 'latest') {
    const v = WANTED.replace(/^v/, '');
    return process.nextTick(() => cb(null, v));
  }
  fetch(`https://api.github.com/repos/${REPO}/releases/latest`, (err, res) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      res.resume();
      return cb(new Error(`resolve latest release: HTTP ${res.statusCode}`));
    }
    let body = '';
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      try {
        const tag = JSON.parse(body).tag_name;
        if (!tag) throw new Error('no tag_name in latest release');
        cb(null, tag.replace(/^v/, ''));
      } catch (e) {
        cb(e);
      }
    });
  });
}

function downloadTo(res, dest, cb) {
  const file = fs.createWriteStream(dest);
  res.pipe(file);
  file.on('finish', () => file.close(cb));
  file.on('error', cb);
}

function ensureBinary(cb) {
  resolveVersion((err, version) => {
    if (err) return cb(err);
    const asset = platformAsset(version);
    const dest = path.join(os.homedir(), '.cache', 'hesper', version, asset);
    if (fs.existsSync(dest)) {
      try { fs.chmodSync(dest, 0o755); } catch (_) { /* win32 */ }
      return cb(null, dest);
    }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const url = `https://github.com/${REPO}/releases/download/v${version}/${asset}`;
    process.stderr.write(`hesper: fetching ${asset} (v${version})…\n`);
    fetch(url, (ferr, res) => {
      if (ferr) return cb(ferr);
      if (res.statusCode !== 200) {
        res.resume();
        try { fs.unlinkSync(dest); } catch (_) { /* keep dir */ }
        return cb(new Error(`download ${asset}: HTTP ${res.statusCode} (no release asset yet? build from source: go build ./cmd/hesper)`));
      }
      downloadTo(res, dest, (derr) => {
        if (derr) return cb(derr);
        fs.chmodSync(dest, 0o755);
        cb(null, dest);
      });
    });
  });
}

ensureBinary((err, bin) => {
  if (err) {
    process.stderr.write(`hesper: ${err.message}\n`);
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
