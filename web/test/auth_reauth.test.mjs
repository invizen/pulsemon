// Frontend regression pins (external review L1, 2026-11-23) — the
// current-password reauth gate on destructive account operations:
// add-user, remove-user, and disable-auth. A stolen session cookie
// must not win account-level decisions, so the UI must collect the
// operator's current password before each of those calls.
//
// Run with:
//   node --test web/test/auth_reauth.test.mjs
// (explicit file: Node 22's --test does not accept a directory argument)
//
// Same vm-harness recipe as frontend.test.mjs: load the REAL web/app.js
// into a Node vm context with a minimal DOM shim; sabotage (reverting
// the fix) makes the matching pin fail.

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
  // Let boot()'s async startup chain settle before the test acts.
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

// ---------- L1a: index.html ships the reauth surface ----------

test('index.html: add-user box carries a current-password input', () => {
  const m = INDEX_HTML.match(/<input id="auth-new-current"[^>]*>/);
  assert.ok(m, 'auth-new-current input missing from the add-user box');
  assert.ok(/type="password"/.test(m[0]), 'auth-new-current must be a password field');
  assert.ok(/autocomplete="current-password"/.test(m[0]),
    'auth-new-current must mark autocomplete="current-password" for the browser password manager');
});

test('index.html: account modal wraps are addressable by id', () => {
  // The confirm-mode dialog must be able to hide the username, new and
  // confirm-password fields — that needs the wrap ids.
  for (const id of ['acc-modal-user-wrap', 'acc-modal-current-wrap', 'acc-modal-new-wrap', 'acc-modal-confirm-wrap']) {
    assert.ok(INDEX_HTML.includes(`id="${id}"`), `modal wrap id="${id}" missing from index.html`);
  }
});

// ---------- L1b: addAuthUser sends current_password ----------

test('addAuthUser: the admin-add POST carries the current password', async () => {
  const app = await makeApp();
  const el = (id) => app.doc.getElementById(id);
  // DOM state exactly as the operator fills it in the add-user box.
  el('auth-new-current').value = 'secretpw';
  el('auth-new-username').value = 'helper';
  el('auth-new-password').value = 'helperpw1';

  let sent = null;
  app.setFetch(async (url, opts) => {
    if (url === '/api/auth/users' && opts && opts.method === 'POST') {
      sent = JSON.parse(opts.body);
      return resp({ ok: true });
    }
    return resp({});
  });
  await app.call('addAuthUser');

  assert.ok(sent, 'addAuthUser sent no POST at all');
  assert.equal(sent.username, 'helper');
  assert.equal(sent.password, 'helperpw1');
  assert.equal(sent.current_password, 'secretpw',
    'the add-user POST must carry the session\'s current password (L1)');
  // The boxes reset after a successful add.
  assert.equal(el('auth-new-current').value, '');
  assert.equal(el('auth-new-username').value, '');
});

// ---------- L1c: remove-user goes through the password modal ----------

test('removeAuthUser: opens the confirm modal and sends no DELETE until the password verifies', async () => {
  const app = await makeApp();
  let deleteSent = null;
  app.setFetch(async (url, opts) => {
    if (url.startsWith('/api/auth/users/') && opts && opts.method === 'DELETE') {
      deleteSent = { url, body: opts.body ? JSON.parse(opts.body) : null };
      return resp({ ok: true });
    }
    return resp({});
  });

  // Clicking Remove must NOT fire the DELETE — it arms the password gate.
  app.call('removeAuthUser', 'bob');
  assert.equal(deleteSent, null, 'Remove fired a DELETE before the current password was collected');
  const modal = app.doc.getElementById('acc-modal');
  assert.ok(!modal.classList.contains('hidden'), 'confirm modal did not open');
  assert.ok(app.doc.getElementById('acc-modal-current-wrap').classList.contains('hidden') === false,
    'the current-password field must be visible in confirm mode');
  assert.ok(app.doc.getElementById('acc-modal-new-wrap').classList.contains('hidden'),
    'the new-password field must stay hidden in confirm mode');

  // Submitting with an EMPTY password must not fire either.
  app.doc.getElementById('acc-p0').value = '';
  await app.call('submitAccountModal');
  assert.equal(deleteSent, null, 'an empty current password must not fire the DELETE');

  // With the password, the DELETE goes out with current_password in the body.
  app.doc.getElementById('acc-p0').value = 'secretpw';
  await app.call('submitAccountModal');
  assert.ok(deleteSent, 'the DELETE never fired after a valid current password');
  assert.equal(deleteSent.url, '/api/auth/users/bob');
  assert.equal(deleteSent.body.current_password, 'secretpw',
    'the DELETE must carry the current password (L1)');
});

// ---------- L1d: disable-auth goes through the two-click arm + password modal ----------

test('confirmDisableAuth: two-click arm then password gate before the disable POST', async () => {
  const app = await makeApp();
  let disableSent = null;
  app.setFetch(async (url, opts) => {
    if (url === '/api/auth/disable' && opts && opts.method === 'POST') {
      disableSent = opts.body ? JSON.parse(opts.body) : {};
      return resp({ enabled: false, authed: false, bootstrapped: true });
    }
    return resp({});
  });

  const btn = app.doc.getElementById('auth-disable-btn');
  // The element must cross the vm boundary BY REFERENCE (app.call()
  // JSON-stringifies its args, which would copy the element).
  app.ctx.__btn = btn;
  // First click arms the two-click confirm.
  await app.get('(confirmDisableAuth)(__btn)');
  assert.equal(btn.dataset.confirming, 'true', 'first click must arm the confirm');
  assert.equal(disableSent, null, 'a single click must not disable auth');

  // Second click: the arm is spent — the password modal opens, no POST yet.
  await app.get('(confirmDisableAuth)(__btn)');
  assert.equal(disableSent, null, 'the second click must not disable auth before the password');
  const modal = app.doc.getElementById('acc-modal');
  assert.ok(!modal.classList.contains('hidden'), 'the password modal must open on the armed second click');

  // Password verifies → the disable POST goes out with current_password.
  app.doc.getElementById('acc-p0').value = 'secretpw';
  await app.call('submitAccountModal');
  assert.ok(disableSent, 'the disable POST never fired after a valid current password');
  assert.equal(disableSent.current_password, 'secretpw',
    'the disable POST must carry the current password (L1)');
});

// ---------- L1e: bootstrap create mode is UNTOUCHED ----------

test('bootstrap: Create First Account sends NO current_password (no session exists)', async () => {
  const app = await makeApp();
  let usersSent = null;
  app.setFetch(async (url, opts) => {
    if (url === '/api/auth/users' && opts && opts.method === 'POST') {
      usersSent = JSON.parse(opts.body);
      return resp({ ok: true });
    }
    if (url === '/api/auth/login' && opts && opts.method === 'POST') {
      return resp({ enabled: true, authed: true, user: 'admin' });
    }
    if (url === '/api/auth/users') return resp([]);
    return resp({});
  });

  app.call('openFirstAccountDialog');
  const el = (id) => app.doc.getElementById(id);
  el('acc-u').value = 'admin';
  el('acc-p').value = 'secretpw';
  el('acc-p2').value = 'secretpw';
  await app.call('submitAccountModal');

  assert.ok(usersSent, 'bootstrap create sent no POST at all');
  assert.equal(usersSent.username, 'admin');
  assert.equal(usersSent.password, 'secretpw');
  assert.ok(!('current_password' in usersSent),
    'bootstrap must NOT send current_password — there is no session to reauth (L1 keeps the first account open)');
});
