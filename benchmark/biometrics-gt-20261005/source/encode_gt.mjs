// Execute the maintained upload codec in an isolated, local headless Chrome.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const manifestPath = path.join(root, 'GT_MANIFEST.json');
const manifestBytes = fs.readFileSync(manifestPath);
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const manifest = JSON.parse(manifestBytes);
const images = manifest.images.filter(im => im.frontend);
const shared = '/workspace/maintained/demo/dual_view/static/shared.js';
const sharedBytes = fs.readFileSync(shared);
const sharedHash = hash(sharedBytes);
if (sharedHash !== manifest.sources[shared]) throw Error('Codec drift');
const output = path.join(root, 'encoded');
const profile = path.join(root, 'chrome-profile');
fs.mkdirSync(output); fs.mkdirSync(profile);
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.url === '/shared.js') {
    res.setHeader('Content-Type', 'text/javascript');
    res.end(sharedBytes);
  } else if (/^\/image\/\d+$/.test(req.url)) {
    const index = Number(req.url.split('/').pop());
    const item = manifest.images[index];
    if (!item || !item.frontend) { res.writeHead(404); res.end(); return; }
    const bytes = fs.readFileSync(item.path);
    if (hash(bytes) !== item.sha256) { res.writeHead(409); res.end(); return; }
    res.setHeader('Content-Type', 'image/jpeg'); res.end(bytes);
  } else if (req.url === '/') {
    res.setHeader('Content-Type', 'text/html'); res.end('<!doctype html><html><body></body></html>');
  } else { res.writeHead(404); res.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const stderr = fs.openSync(path.join(root, 'chrome.stderr.log'), 'wx');
const browser = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
  '--headless', '--disable-background-networking', '--disable-component-update',
  '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0',
  '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, 'about:blank',
], { stdio: ['ignore', 'ignore', stderr] });
fs.writeFileSync(path.join(root, 'GT_CODEC_STARTED.json'), JSON.stringify({
  utc: new Date().toISOString(), pid: process.pid, owned_browser_pid: browser.pid,
  manifest_sha256: hash(manifestBytes), local_only: true,
}, null, 2));
let socket;
let seq = 0;
const pending = new Map();
function send(method, params = {}, sessionId) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(Error(`Owned browser RPC timed out: ${method}`));
    }, 10000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
function rejectPending(reason) {
  for (const waiter of pending.values()) {
    clearTimeout(waiter.timer);
    waiter.reject(Error(reason));
  }
  pending.clear();
}
const running = () => browser.exitCode === null && browser.signalCode === null;
async function waitChild(milliseconds) {
  if (!running()) return true;
  let listener;
  let timer;
  const exited = new Promise(resolve => { listener = () => resolve(true); browser.once('exit', listener); });
  const expired = new Promise(resolve => { timer = setTimeout(() => resolve(false), milliseconds); });
  const result = await Promise.race([exited, expired]);
  clearTimeout(timer);
  browser.removeListener('exit', listener);
  return result;
}
try {
  const portFile = path.join(profile, 'DevToolsActivePort');
  const deadline = Date.now() + 30000;
  while (!fs.existsSync(portFile)) {
    if (browser.exitCode !== null || Date.now() > deadline) throw Error('Owned Chrome did not become ready');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  const [port, wsPath] = fs.readFileSync(portFile, 'utf8').trim().split('\n');
  socket = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeEventListener('open', opened);
      socket.removeEventListener('error', failed);
      socket.removeEventListener('close', failed);
      browser.removeListener('exit', failed);
    };
    const opened = () => { cleanup(); resolve(); };
    const failed = () => { cleanup(); reject(Error('Owned browser connection failed or timed out')); };
    const timer = setTimeout(failed, 10000);
    socket.addEventListener('open', opened, { once: true });
    socket.addEventListener('error', failed, { once: true });
    socket.addEventListener('close', failed, { once: true });
    browser.once('exit', failed);
  });
  socket.onclose = () => rejectPending('Owned browser connection closed');
  socket.onerror = () => rejectPending('Owned browser connection failed');
  socket.onmessage = ({ data }) => {
    const value = JSON.parse(data);
    const waiter = pending.get(value.id);
    if (!waiter) return;
    pending.delete(value.id);
    clearTimeout(waiter.timer);
    value.error ? waiter.reject(Error(JSON.stringify(value.error))) : waiter.resolve(value.result);
  };
  const version = await send('Browser.getVersion');
  const target = await send('Target.createTarget', { url: origin });
  const attached = await send('Target.attachToTarget', { targetId: target.targetId, flatten: true });
  const records = [];
  for (const image of images) {
    const expression = `(async()=>{
      const {readPhotos}=await import(${JSON.stringify(origin + '/shared.js')});
      const bytes=await (await fetch(${JSON.stringify(origin + '/image/' + image.index)})).arrayBuffer();
      return (await readPhotos([new File([bytes], 'input.jpg', {type:'image/jpeg'})]))[0];
    })()`;
    const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, attached.sessionId);
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    const data = result.result.value;
    if (typeof data !== 'string' || !data.startsWith('data:image/jpeg;base64,')) throw Error('Missing JPEG');
    const bytes = Buffer.from(data.split(',')[1], 'base64');
    const file = path.join(output, `${image.index}.jpg`);
    fs.writeFileSync(file, bytes, { flag: 'wx' });
    records.push({ index: image.index, path: file, bytes: bytes.length, sha256: hash(bytes) });
    if (records.length % 50 === 0) process.stdout.write(JSON.stringify({ stage: 'codec', done: records.length }) + '\n');
  }
  fs.writeFileSync(path.join(root, 'GT_ENCODING.json'), JSON.stringify({
    utc: new Date().toISOString(), manifest_sha256: hash(manifestBytes), version,
    codec_source_sha256: sharedHash, images: records,
    local_only: true, recognizer_executed: false,
  }, null, 2), { flag: 'wx' });
  process.stdout.write(JSON.stringify({ status: 'ENCODED', images: records.length, browser: version.product }) + '\n');
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    await send('Browser.close').catch(() => {});
  }
  if (socket && socket.readyState !== WebSocket.CLOSED) {
    try { socket.close(); } catch {}
  }
  rejectPending('Codec cleanup');
  // Only this newly spawned child object may be signalled; no stored/user PID.
  const signals = [];
  if (!await waitChild(3000) && running()) {
    browser.kill('SIGTERM'); signals.push('SIGTERM');
  }
  if (!await waitChild(3000) && running()) {
    browser.kill('SIGKILL'); signals.push('SIGKILL');
  }
  const exited = await waitChild(3000);
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  fs.closeSync(stderr);
  fs.writeFileSync(path.join(root, 'GT_CODEC_CLEANUP.json'), JSON.stringify({
    utc: new Date().toISOString(), owned_browser_pid: browser.pid, exited,
    exit_code: browser.exitCode, signal: browser.signalCode, fallback_signals: signals,
    existing_process_control: false,
  }, null, 2), { flag: 'wx' });
  if (!exited) throw Error('Owned browser exit not observed; do not restart codec');
}
