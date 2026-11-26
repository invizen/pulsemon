// Frontend regression pins (2026-11-23 windows-upgrade-safety, item 1) —
// run with:
//   node --test web/test/conn_banner.test.mjs
// (explicit file: Node 22's --test does not accept a directory argument)
//
// The #conn-banner is the visible half of the startup retry loop: a page
// loaded during the service-down window of an in-dashboard self-update
// (the installer opens the browser ~4s before the service answers) must
// show "waiting for the server", not the silent "no sensors" empty state
// that reads as "the sensors were wiped". refresh() drives the banner
// from the fetch outcome; the 5s poller is the retry.
//
// These pins load the REAL web/app.js (not a copy) into a Node `vm`
// context with a minimal DOM shim (same harness as frontend.test.mjs).
// Sabotage (reverting the banner wiring) makes the matching pin fail.
// History: docs/DECISIONS.md → windows-upgrade-safety

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_JS = fs.readFileSync(path.join(here, '..', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(here, '..', 'index.html'), 'utf8');

const resp = (obj, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: 'OK',
  json: async () => obj,
});

function makeClassList() {
  const s = new Set();
  return {
    add: (...cs) => cs.forEach(c => s.add(c)),
    remove: (...cs) => cs.forEach(c => s.delete(c)),
    toggle(c, force) {
      const on = force === undefined ? !s.has(c) : !!force;
      if (on) s.add(c); else s.delete(c);
      return on;
    },
    contains: (c) => s.has(c),
  };
}

function makeEl(id) {
  return {
    id, value: '', textContent: '', innerHTML: '', className: '',
    placeholder: '', title: '', disabled: false, clientWidth: 0,
    files: [], options: [],
    style: {}, dataset: {}, classList: makeClassList(),
    addEventListener() {}, removeEventListener() {},
    appendChild() {}, remove() {}, focus() {}, click() {},
    querySelector() { return null; }, querySelectorAll() { return []; },
    closest() { return null; },
  };
}

// makeAppWithFetch: the frontend.test.mjs harness with the boot-time fetch
// swappable BEFORE app.js loads, so the pins can start the page against a
// DEAD server (the upgrade-restart window) and then bring it back.
async function makeAppWithFetch(initialFetch) {
  const els = new Map();
  const listeners = {};
  const doc = {
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement(tag) { return makeEl('dyn-' + tag); },
    addEventListener(type, fn) { (listeners[type] ||= []).push(fn); },
    visibilityState: 'visible',
    documentElement: makeEl('html'),
    body: makeEl('body'),
  };
  const sandbox = {
    console,
    document: doc,
    window: { addEventListener() {}, devicePixelRatio: 1 },
    location: { hostname: 'localhost', port: '9299', href: 'http://localhost:9299/', reload() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    localStorage: {
      _m: new Map(),
      getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
      setItem(k, v) { this._m.set(k, String(v)); },
      removeItem(k) { this._m.delete(k); },
    },
    fetch: initialFetch,
    setInterval: () => 0,
    setTimeout: () => 0,
    clearInterval() {},
    clearTimeout() {},
    getComputedStyle: () => ({ paddingLeft: '0px', paddingRight: '0px' }),
    confirm: () => false,
    alert() {},
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(APP_JS, ctx, { filename: 'app.js' });
  // Settle boot()'s async chain (checkAuth → startPolling → refresh).
  for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r));
  return {
    doc,
    ctx,
    setFetch(fn) { sandbox.fetch = fn; },
    get(expr) { return vm.runInContext(expr, ctx); },
    call(fn, ...args) { return vm.runInContext(`(${fn}).apply(null, ${JSON.stringify(args)})`, ctx); },
  };
}

// A dead server: every fetch rejects (connection refused).
const deadFetch = async () => { throw new Error('connect ECONNREFUSED 127.0.0.1:9299'); };

// A live server answering the startup fetches.
const liveFetch = async (url) => {
  if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
  if (url === '/api/sensors') return resp([{ id: 'a', name: 'a', target: '127.0.0.1', type: 'icmp', state: 'active' }]);
  if (url.startsWith('/api/events')) return resp([]);
  if (url === '/api/healthz') return resp({ version: '0.0.0-test', sensors: 1 });
  if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
  return resp({});
};

const ticks = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise(r => setImmediate(r)); };

test('index.html ships the conn-banner element', () => {
  assert.ok(/id="conn-banner"/.test(INDEX_HTML), 'conn-banner element missing from index.html');
  assert.ok(/id="conn-banner-text"/.test(INDEX_HTML), 'conn-banner-text element missing from index.html');
});

test('server down at page load: the banner is shown (not a silent empty grid)', async () => {
  const app = await makeAppWithFetch(deadFetch);
  // boot() ran against the dead server: checkAuth fell back to auth-off,
  // startPolling() ran refresh() once and it failed.
  const banner = app.doc.getElementById('conn-banner');
  assert.ok(!banner.classList.contains('hidden'),
    'a page loaded while the server is down must show the waiting banner');
  assert.match(app.doc.getElementById('conn-banner-text').textContent, /server/i,
    'the banner text must name the server');
});

test('server comes back: the next refresh hides the banner', async () => {
  const app = await makeAppWithFetch(deadFetch);
  assert.ok(!app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'precondition: banner visible while the server is down');
  app.setFetch(liveFetch);
  await app.call('refresh');
  await ticks();
  assert.ok(app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'a successful refresh must hide the waiting banner');
  assert.equal(app.get('connFails'), 0, 'the failure counter must reset');
  assert.equal(app.get('SENSORS').length, 1, 'the sensors must land after the recovery');
});

test('persistent outage: the text escalates to an actionable message', async () => {
  const app = await makeAppWithFetch(deadFetch);
  // Two more failed rounds (the 5s poller, compressed into direct calls).
  await app.call('refresh');
  await ticks();
  await app.call('refresh');
  await ticks();
  assert.equal(app.get('connFails'), 3, 'three consecutive failures expected');
  const text = app.doc.getElementById('conn-banner-text').textContent;
  assert.match(text, /check the pulsemon service/i,
    'after 3 failures the banner must tell the operator to check the service, got: ' + text);
});

test('positive control: a server that is up from the start never shows the banner', async () => {
  const app = await makeAppWithFetch(liveFetch);
  assert.ok(app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'a healthy startup must not flash the waiting banner');
  assert.equal(app.get('connFails'), 0);
});

// Recovery from the server-down (fail-closed auth) state must RE-FETCH the
// status: the server is answering again, so its answer is authoritative
// again — auth enabled + unauthed brings the gate back (the inoperable
// banner gave way to a working login form), auth off keeps the gate hidden
// (the fail-closed value must not outlive the outage, 2026-11-26).
test('recovery with auth enabled: the gate appears after the waiting banner', async () => {
  const app = await makeAppWithFetch(deadFetch);
  assert.ok(!app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'precondition: banner visible while the server is down');
  app.setFetch(async (url) => {
    if (url === '/api/auth/status') return resp({ enabled: true, authed: false });
    return liveFetch(url);
  });
  await app.call('refresh');
  await ticks();
  assert.ok(app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'recovery must hide the waiting banner');
  assert.equal(app.get('connFails'), 0);
  assert.ok(!app.doc.getElementById('auth-gate').classList.contains('hidden'),
    'auth enabled + unauthed after recovery: the (now working) gate must appear');
});

test('recovery with auth off: no gate, no banner, sensors land', async () => {
  const app = await makeAppWithFetch(deadFetch);
  assert.ok(!app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'precondition: banner visible while the server is down');
  app.setFetch(liveFetch); // liveFetch answers /api/auth/status with auth off
  await app.call('refresh');
  await ticks();
  assert.ok(app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'recovery must hide the waiting banner');
  assert.ok(app.doc.getElementById('auth-gate').classList.contains('hidden'),
    'the fail-closed state must not outlive the outage when auth is off');
  assert.equal(app.get('SENSORS').length, 1, 'sensors must land after recovery');
});
