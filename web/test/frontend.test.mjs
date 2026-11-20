// Frontend regression pins (review 2026-11-19 F16) — run with:
//   node --test web/test/frontend.test.mjs
// (explicit file: Node 22's --test does not accept a directory argument)
//
// These pins load the REAL web/app.js (not a copy) into a Node `vm`
// context with a minimal DOM shim, then exercise the shipped functions.
// Sabotage (reverting the fix) makes the matching pin fail. History:
// docs/DECISIONS.md → frontend-ops-auth-ui-fixes
//
// Shim notes:
//  - Elements are lazily created by document.getElementById (the same
//    instance the app sees), so tests can pre-seed input values exactly
//    as renderProviderList()/index.html would.
//  - setInterval/setTimeout are NO-OPS: the 5s/10min poll loops are not
//    under test, and real timers would keep the test process alive.
//  - Top-level `let` bindings (meIsAdmin, SETTINGS, authState) live in
//    the context's global scope, not on the sandbox object — read/write
//    them through vm.runInContext expressions.

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

async function makeApp() {
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
    // Base responses cover boot()'s startup fetches; tests override.
    fetch: async (url) => {
      if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
      if (url === '/api/sensors') return resp([]);
      if (url.startsWith('/api/events')) return resp([]);
      if (url === '/api/healthz') return resp({ version: '0.0.0-test' });
      if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
      return resp({});
    },
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
  // Let boot()'s async startup chain (checkAuth → startPolling → refresh
  // → checkUpdate) settle against the base fetch before the test acts.
  for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r));
  return {
    doc,
    ctx,
    setFetch(fn) { sandbox.fetch = fn; },
    get(expr) { return vm.runInContext(expr, ctx); },
    set(name, val) { vm.runInContext(`${name} = ${JSON.stringify(val)}`, ctx); },
    call(fn, ...args) { return vm.runInContext(`(${fn}).apply(null, ${JSON.stringify(args)})`, ctx); },
    fire(type, ev) { (listeners[type] || []).forEach(fn => fn(ev)); },
  };
}

// ---------- F16a: TLS port box stuck at 443 ----------

test('TLS port box: index.html ships no hardcoded 443 default', () => {
  const m = INDEX_HTML.match(/<input id="f-tls-port"[^>]*>/);
  assert.ok(m, 'f-tls-port input missing from index.html');
  assert.ok(!/value="443"/.test(m[0]),
    'f-tls-port hardcodes value="443" — renderTLSStatus() can never seed the real port');
});

test('TLS port box: renderTLSStatus seeds it from the server port (custom port survives)', () => {
  const app = makeAppSync();
  // The old HTML shipped value="443"; simulate that stale default.
  app.doc.getElementById('f-tls-port').value = '443';
  app.call('renderTLSStatus', { enabled: true, port: 8443, source: 'file' });
  assert.equal(String(app.doc.getElementById('f-tls-port').value), '8443',
    'a cert renewed on 8443 must stay 8443 when the panel re-renders');
});

test('TLS port box: falls back to 443 when the server reports no port', () => {
  const app = makeAppSync();
  app.doc.getElementById('f-tls-port').value = '8443';
  // removeTLSCert() renders exactly this shape (no port field).
  app.call('renderTLSStatus', { enabled: false, http_addr: 'host:80' });
  assert.equal(String(app.doc.getElementById('f-tls-port').value), '443');
});

// makeApp is async only to settle boot(); these pure-DOM tests need no
// fetch, so a sync wrapper keeps them simple.
function makeAppSync() {
  // Synchronous load: boot() is an IIFE that will run against the base
  // fetch; its async tail settles harmlessly (no test depends on it).
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
    fetch: async (url) => {
      if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
      if (url === '/api/sensors') return resp([]);
      if (url.startsWith('/api/events')) return resp([]);
      if (url === '/api/healthz') return resp({ version: '0.0.0-test' });
      if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
      return resp({});
    },
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
  return {
    doc,
    ctx,
    setFetch(fn) { sandbox.fetch = fn; },
    get(expr) { return vm.runInContext(expr, ctx); },
    set(name, val) { vm.runInContext(`${name} = ${JSON.stringify(val)}`, ctx); },
    call(fn, ...args) { return vm.runInContext(`(${fn}).apply(null, ${JSON.stringify(args)})`, ctx); },
    fire(type, ev) { (listeners[type] || []).forEach(fn => fn(ev)); },
  };
}

// ---------- F16b: saveAlerts drops masked-URL providers & trims SMTP creds ----------

test('saveAlerts: masked-URL providers stay in the save and keep their extra edits', async () => {
  const app = await makeApp();
  // Server-stored providers as /api/settings returns them: the Telegram
  // bot token is MASKED (***…***), the SMTP host is plain.
  app.set('SETTINGS', { providers: [
    { kind: 'telegram', url: 'https://api.telegram.org/bot***:REDACTED/...', enabled: true,
      extra: { chat_id: '111' } },
    { kind: 'smtp', url: 'smtp.example.com', enabled: true,
      extra: { port: '587', from: 'pulsemon@example.com', to: 'ops@example.com',
               username: 'user@example.com', password: '••••••••', tls_mode: 'auto' } },
    { kind: 'discord', url: 'https://discord.example/api/webhooks/1/x', enabled: true, extra: {} },
  ] });
  // DOM state EXACTLY as renderProviderList() renders it: masked token →
  // BLANK url box (urlVal = masked ? '' : p.url), chat_id box seeded,
  // operator edited the chat_id to 222.
  app.doc.getElementById('prov-url-telegram').value = '';
  app.doc.getElementById('prov-chatid-telegram').value = '222';
  app.doc.getElementById('prov-url-smtp').value = 'smtp.example.com';
  app.doc.getElementById('prov-smtp-port').value = '587';
  app.doc.getElementById('prov-smtp-from').value = 'pulsemon@example.com';
  app.doc.getElementById('prov-smtp-to').value = 'ops@example.com';
  // Credentials with meaningful edge spaces (the server stores them RAW).
  app.doc.getElementById('prov-smtp-user').value = ' ' + 'user@example.com' + ' ';
  app.doc.getElementById('prov-smtp-pass').value = 'p' + ' w ';
  app.doc.getElementById('prov-smtp-tls').value = 'auto';
  app.doc.getElementById('prov-url-discord').value = 'https://discord.example/api/webhooks/1/x';
  app.doc.getElementById('f-scope').value = 'all';
  app.doc.getElementById('f-realert').value = '30';

  let sent = null;
  app.setFetch(async (url, opts) => {
    if (url === '/api/settings' && opts && opts.method === 'PUT') {
      sent = JSON.parse(opts.body);
      return resp({ providers: app.get('SETTINGS').providers });
    }
    return resp({});
  });
  await app.call('saveAlerts');

  assert.ok(sent, 'settings PUT was not sent at all');
  assert.deepEqual(sent.providers.map(p => p.kind).sort(), ['discord', 'smtp', 'telegram'],
    'the blank-URL (masked) telegram provider must NOT be filtered out');
  const tg = sent.providers.find(p => p.kind === 'telegram');
  assert.equal(tg.extra.chat_id, '222', 'the chat_id edit was silently dropped');
  assert.ok(!('url' in tg), 'blank url must be OMITTED (server nil-url = keep stored), not sent empty');
  const sm = sent.providers.find(p => p.kind === 'smtp');
  assert.equal(sm.url, 'smtp.example.com');
  assert.equal(sm.extra.username, ' user@example.com ', 'SMTP username must be sent untrimmed');
  assert.equal(sm.extra.password, 'p w ', 'SMTP password must be sent untrimmed');
  const dc = sent.providers.find(p => p.kind === 'discord');
  assert.equal(dc.url, 'https://discord.example/api/webhooks/1/x', 'a typed url must still be sent');
});

// ---------- F16c: stale meIsAdmin on re-login ----------

test('doLogin: re-login in the same tab re-resolves admin state (role switch)', async () => {
  const app = await makeApp();
  const USERS = { adm: true, vie: false };
  let currentUser = null;
  app.setFetch(async (url, opts) => {
    if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
    if (url === '/api/auth/login' && opts && opts.method === 'POST') {
      const body = JSON.parse(opts.body);
      currentUser = body.username;
      return resp({ enabled: true, authed: true, user: currentUser });
    }
    if (url === '/api/auth/users') return resp([{ username: currentUser, is_admin: USERS[currentUser] }]);
    if (url === '/api/sensors') return resp([]);
    if (url.startsWith('/api/events')) return resp([]);
    if (url === '/api/healthz') return resp({ version: '0.0.0-test' });
    if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
    return resp({});
  });
  // boot() already armed the pollers (auth-off page load), so EVERY
  // doLogin below is the re-login path where startPolling() no-ops.
  assert.equal(await app.call('doLogin', 'adm', 'pw-1'), true, 'admin login failed');
  assert.equal(app.get('meIsAdmin'), true, 'admin surface must be visible after admin login');
  assert.equal(await app.call('doLogin', 'vie', 'pw-2'), true, 'viewer login failed');
  assert.equal(app.get('meIsAdmin'), false,
    'viewer re-login must hide the admin surface (stale meIsAdmin)');
  assert.equal(await app.call('doLogin', 'adm', 'pw-3'), true, 're-promotion login failed');
  assert.equal(app.get('meIsAdmin'), true,
    'admin re-login must show the admin surface again');
});

// ---------- F16d: update pill un-gated from meIsAdmin ----------

test('renderUpdateUI: the update pill is gated on meIsAdmin', () => {
  const app = makeAppSync();
  const up = { running: '1.0.0', latest: '1.1.0', available: true,
    url: 'https://github.com/invizen/pulsemon/releases' };
  const pill = () => app.doc.getElementById('update-pill');
  app.set('meIsAdmin', false);
  app.call('renderUpdateUI', up);
  assert.ok(pill().classList.contains('hidden'),
    'a viewer must not see the pill (it opens the admin-gated Settings modal)');
  app.set('meIsAdmin', true);
  app.call('renderUpdateUI', up);
  assert.ok(!pill().classList.contains('hidden'),
    'an admin must see the pill when an update is available');
  // Positive control: up-to-date → hidden even for an admin.
  app.call('renderUpdateUI', { running: '1.1.0', latest: '1.1.0', available: false,
    url: 'https://github.com/invizen/pulsemon/releases' });
  assert.ok(pill().classList.contains('hidden'), 'no update → pill hidden');
});

// ---------- Nits (2026-11-20): UI polish ----------

test('sensor form: #f-interval min matches the backend floor (5s)', () => {
  const m = INDEX_HTML.match(/<input id="f-interval"[^>]*>/);
  assert.ok(m, 'f-interval input missing from index.html');
  assert.ok(/min="5"/.test(m[0]),
    'f-interval min must be 5 (backend minIntervalS=5), got: ' + m[0]);
});

test('Escape closes the Alerts modal', () => {
  const app = makeAppSync();
  const bd = app.doc.getElementById('alerts-backdrop');
  bd.classList.remove('hidden'); // simulate the modal open
  app.fire('keydown', { key: 'Escape' });
  assert.ok(bd.classList.contains('hidden'),
    'Escape must close the Alerts modal (closeAlerts was missing from the handler)');
});

test('applyAdminVisibility: a viewer does not see the clear-activity button', () => {
  const app = makeAppSync();
  const btn = () => app.doc.getElementById('clear-activity-btn');
  app.set('meIsAdmin', false);
  app.call('applyAdminVisibility');
  assert.ok(btn().classList.contains('hidden'),
    'a viewer must not see the clear-activity button');
  app.set('meIsAdmin', true);
  app.call('applyAdminVisibility');
  assert.ok(!btn().classList.contains('hidden'),
    'an admin must see the clear-activity button');
});
