// Auth-gate regression pins (2026-11-25 external review MINOR-25) — run with:
//   node --test web/test/auth_gate.test.mjs
// (explicit file: Node 22's --test does not accept a directory argument)
//
// Pins the real web/app.js (not a copy) in a Node `vm` sandbox, the same
// harness shape as frontend.test.mjs:
//  - showAuthGate() must SANITIZE the dashboard it covers (stale SENSORS
//    carry target credentials; open admin modals outlive the overlay).
//  - checkAuth() must not fabricate state from a non-2xx /api/auth/status
//    (a 502 used to set authed:true — unlocking the dashboard during
//    proxy blips) and must fail CLOSED on a first-load network failure.
//  - the admin flag rides the status/login response (is_admin) — no
//    /api/auth/users round-trip per page load.
// History: docs/DECISIONS.md → auth-gate-sanitize

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_JS = fs.readFileSync(path.join(here, '..', 'app.js'), 'utf8');

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

const MODALS = ['settings-backdrop', 'alerts-backdrop', 'acc-modal', 'modal-backdrop', 'insp-backdrop'];

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
  // Settle boot()'s async startup chain (checkAuth → startPolling →
  // refresh → checkUpdate) against the base fetch before the test acts.
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

// ---------- showAuthGate sanitizes ----------

test('showAuthGate: clears stale data and closes every modal', async () => {
  const app = await makeApp();
  // Simulate a logged-in admin session with data + every modal open.
  app.set('SENSORS', [{ name: 'nas', target: 'https://user:pass@nas.lan/health', tags: [] }]);
  app.set('EVENTS', [{ msg: 'nas up' }]);
  app.set('SETTINGS', { providers: [{ kind: 'smtp', extra: { password: '••••••••' } }] });
  app.set('authState', { enabled: true, authed: true, user: 'admin', is_admin: true });
  for (const id of MODALS) app.doc.getElementById(id).classList.remove('hidden');

  app.call('showAuthGate');

  // JSON-normalize: app.get() returns objects from the VM realm, and
  // deepStrictEqual is prototype-strict across realms.
  const J = v => JSON.parse(JSON.stringify(v));
  assert.deepEqual(J(app.get('SENSORS')), [], 'SENSORS must be cleared (targets carry credentials)');
  assert.deepEqual(J(app.get('EVENTS')), [], 'EVENTS must be cleared');
  assert.deepEqual(J(app.get('SETTINGS')), {}, 'SETTINGS must be cleared (provider secrets)');
  for (const id of MODALS) {
    assert.ok(app.doc.getElementById(id).classList.contains('hidden'), id + ' must be closed when the gate shows');
  }
  assert.ok(!app.doc.getElementById('auth-gate').classList.contains('hidden'), 'the gate itself must be shown');
});

// ---------- checkAuth state handling ----------

test('checkAuth: a 502 with the gate up does NOT unlock the dashboard', async () => {
  const app = await makeApp();
  app.set('authState', { enabled: true, authed: false }); // gate showing
  app.setFetch(async () => resp({}, 502));
  const ok = await app.call('checkAuth');
  assert.equal(ok, false, 'a 502 must not report "proceed"');
  // JSON-normalize: cross-realm objects fail prototype-strict deepEqual.
  assert.deepEqual(JSON.parse(JSON.stringify(app.get('authState'))), { enabled: true, authed: false },
    'the prior state must be preserved (the old code set authed:true on non-2xx)');
  assert.ok(!app.doc.getElementById('auth-gate').classList.contains('hidden'), 'the gate must stay up');
});

test('checkAuth: a 502 with a live session preserves the session', async () => {
  const app = await makeApp();
  const prior = { enabled: true, authed: true, user: 'admin', is_admin: true };
  app.set('authState', prior);
  app.setFetch(async () => resp({}, 502));
  const ok = await app.call('checkAuth');
  assert.equal(ok, true, 'a live session must survive a status blip');
  assert.deepEqual(JSON.parse(JSON.stringify(app.get('authState'))), prior, 'no fabricated state on a blip');
});

test('checkAuth: first-load network failure fails closed (banner, not gate)', async () => {
  const app = await makeApp();
  app.set('authState', null);
  app.setFetch(async () => { throw new Error('network down'); });
  const ok = await app.call('checkAuth');
  assert.equal(ok, false, 'no evidence = no unlock');
  assert.deepEqual(JSON.parse(JSON.stringify(app.get('authState'))), { enabled: true, authed: false },
    'first-load failure must fail CLOSED on the STATE (the old code set enabled:false, dismissing the gate)');
  // The UI is the waiting banner, not the login gate: the server is
  // unreachable, so the form cannot work and there is no data to hide —
  // a 200 status after recovery decides the gate (2026-11-26: the gate
  // shape here re-broke the conn-banner upgrade-window contract,
  // windows-upgrade-safety).
  assert.ok(!app.doc.getElementById('conn-banner').classList.contains('hidden'),
    'the waiting banner must show while the server is unreachable');
  assert.ok(app.doc.getElementById('auth-gate').classList.contains('hidden'),
    'the inoperable login gate must not cover the banner');
});

// ---------- is_admin rides the login/status response ----------

test('doLogin: is_admin comes from the login response (no /api/auth/users round-trip)', async () => {
  const app = await makeApp();
  let usersCalls = 0;
  app.setFetch(async (url, opts) => {
    if (url === '/api/auth/login' && opts && opts.method === 'POST') {
      const body = JSON.parse(opts.body);
      return resp({ enabled: true, authed: true, user: body.username, is_admin: body.username === 'adm' });
    }
    if (url === '/api/auth/users') { usersCalls++; return resp([]); }
    if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
    if (url === '/api/sensors') return resp([]);
    if (url.startsWith('/api/events')) return resp([]);
    if (url === '/api/healthz') return resp({ version: '0.0.0-test' });
    if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
    return resp({});
  });
  assert.equal(await app.call('doLogin', 'adm', 'pw-1'), true, 'admin login failed');
  assert.equal(app.get('meIsAdmin'), true, 'the admin surface must be visible after an admin login');
  assert.equal(await app.call('doLogin', 'vie', 'pw-2'), true, 'viewer login failed');
  assert.equal(app.get('meIsAdmin'), false,
    'a viewer re-login must hide the admin surface (is_admin:false from the server)');
  assert.equal(usersCalls, 0,
    'no /api/auth/users round-trip is allowed — is_admin rides the login response');
});
