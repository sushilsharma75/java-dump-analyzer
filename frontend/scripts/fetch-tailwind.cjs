#!/usr/bin/env node
/*
 * Downloads the Tailwind CSS *standalone* CLI — a single self-contained binary
 * that compiles @tailwind / @apply with NO PostCSS in the dependency tree or
 * build pipeline. Idempotent: skips the download if the binary already exists.
 *
 * Override the version with TAILWIND_VERSION; the binary lands in ./bin.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

const VERSION = process.env.TAILWIND_VERSION || 'v3.4.15';
const BIN_DIR = path.resolve(__dirname, '..', 'bin');
const isWindows = process.platform === 'win32';
const BIN_PATH = path.join(BIN_DIR, isWindows ? 'tailwindcss.exe' : 'tailwindcss');

function assetName() {
  const platform = { linux: 'linux', darwin: 'macos', win32: 'windows' }[process.platform];
  const arch = { x64: 'x64', arm64: 'arm64' }[process.arch];
  if (!platform || !arch) {
    throw new Error(`Unsupported platform/arch: ${process.platform}/${process.arch}`);
  }
  return `tailwindcss-${platform}-${arch}${isWindows ? '.exe' : ''}`;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'fetch-tailwind' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          // GitHub release assets redirect to a signed CDN URL.
          res.resume();
          return download(res.headers.location, dest).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`Download failed (${res.statusCode}) for ${url}`));
        }
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
        file.on('error', reject);
      })
      .on('error', reject);
  });
}

async function main() {
  if (fs.existsSync(BIN_PATH)) return; // already downloaded

  const asset = assetName();
  const url = `https://github.com/tailwindlabs/tailwindcss/releases/download/${VERSION}/${asset}`;
  fs.mkdirSync(BIN_DIR, { recursive: true });

  console.log(`Fetching Tailwind standalone CLI ${VERSION} (${asset})...`);
  await download(url, BIN_PATH);
  if (!isWindows) fs.chmodSync(BIN_PATH, 0o755);
  console.log(`Tailwind CLI ready at ${path.relative(process.cwd(), BIN_PATH)}`);
}

main().catch((err) => {
  console.error(`\n[fetch-tailwind] ${err.message}`);
  console.error('You can also place the binary manually at frontend/bin/tailwindcss');
  process.exit(1);
});
