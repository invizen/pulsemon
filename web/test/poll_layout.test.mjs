// Frontend regression pins (review F24 — double-poll / layout thrash) — run with:
//   node --test web/test/poll_layout.test.mjs
// (explicit file: Node 22's --test does not accept a directory argument)
//
// These pins load the REAL web/app.js (not a copy) into a Node `vm` context
// with a minimal DOM shim, then exercise the shipped functions. Sabotage
// (reverting the fix) makes the matching pin fail. History:
// docs/DECISIONS.md -> frontend-poll-layout-thrash
//
// Three defects pinned:
//  1. Two 5s intervals both drove loadInspector() -> 2x inspector requests.
//  2. refresh() had no in-flight guard -> a slow refresh let the next tick
//     start a second concurrent one (6 api() calls, interleaved data).
//  3. layoutSparklines() interleaved layout reads (getComputedStyle/
//     clientWidth) with style writes per card -> N forced reflows.
//
// Shim notes (reuse the F16 harness shape):
//  - setInterval is a TRACKING no-op here (not a bare no-op) so the polling
//    pins can enumerate the armed 5s callbacks and fire one simulated tick.
//  - For the layout pin, getComputedStyle / clientWidth / style writes are
//    instrumented to record read/write ORDER, so an interleaved (old) layout
//    fails the "all reads before all writes" assertion.

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

// Base responses cover boot()'s startup fetches; tests override.
function baseFetch(url) {
  if (url === '/api/auth/status') return resp({ enabled: false, authed: false });
  if (url === '/api/sensors') return resp([]);
  if (url.startsWith('/api/events')) return resp([]);
  if (url === '/api/healthz') return resp({ version: '0.0.0-test' });
  if (url.startsWith('/api/update-check')) return resp({ available: false, running: '0.0.0-test' });
  return resp({});
}

// Harness for the polling pins: tracking setInterval + a __liCount global the
// loadInspector spy increments.
async function makePollApp() {
  const els = new Map();
  const intervals = [];
  const doc = {
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement(tag) { return makeEl('dyn-' + tag); },
    addEventListener() {},
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
    fetch: async (url) => baseFetch(url),
    __liCount: 0,
    // TRACKING no-op: record (cb, delay) so a test can fire one simulated tick.
    setInterval: (cb, delay) => { intervals.push({ cb, delay }); return 0; },
    setTimeout: () => 0,
    clearInterval() {},
    clearTimeout() {},
    getComputedStyle: () => ({ paddingLeft: '0px', paddingRight: '0px' }),
    confirm: () => false,
    alert() {},
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(APP_JS, ctx, { filename: 'app.js' });
  // Settle boot()'s async startup chain against the base fetch.
  for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r));
  return {
    doc,
    ctx,
    intervals,
    setFetch(fn) { sandbox.fetch = fn; },
    get(expr) { return vm.runInContext(expr, ctx); },
    set(name, val) { vm.runInContext(`${name} = ${JSON.stringify(val)}`, ctx); },
    call(fn, ...args) { return vm.runInContext(`(${fn}).apply(null, ${JSON.stringify(args)})`, ctx); },
  };
}

// Harness for the layout pin: a fake card/bar DOM with instrumented reads and
// writes so we can assert the read/write ORDER.
function makeLayoutApp() {
  const events = [];
  const trackStyle = () => {
    const t = {};
    return new Proxy(t, {
      set(o, p, v) { if (active) events.push('write'); o[p] = v; return true; },
      get(o, p) { return o[p]; },
    });
  };
  const bars = [];
  const cards = [];
  for (let ci = 0; ci < 3; ci++) {
    const cardBars = Array.from({ length: 60 }, () => {
      const b = { dataset: { h: '50%' }, style: trackStyle(), querySelectorAll: () => [] };
      bars.push(b);
      return b;
    });
    const card = {
      querySelectorAll(sel) { return sel === '.spark-bar' ? cardBars : []; },
    };
    Object.defineProperty(card, 'clientWidth', {
      get() { if (active) events.push('read'); return 320; },
    });
    cards.push(card);
  }
  let active = false; // off during boot, on for the explicit layoutSparklines()
  const els = new Map();
  const doc = {
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id)); return els.get(id); },
    querySelector() { return null; },
    querySelectorAll(sel) {
      if (!active) return [];
      if (sel === '[data-h]') return bars;
      if (sel === '.h-9.flex') return cards;
      return [];
    },
    createElement(tag) { return makeEl('dyn-' + tag); },
    addEventListener() {},
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
    fetch: async (url) => baseFetch(url),
    setInterval: () => 0,
    setTimeout: () => 0,
    clearInterval() {},
    clearTimeout() {},
    getComputedStyle: () => { if (active) events.push('read'); return { paddingLeft: '0px', paddingRight: '0px' }; },
    confirm: () => false,
    alert() {},
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(APP_JS, ctx, { filename: 'app.js' });
  return {
    ctx,
    events,
    activate() { active = true; events.length = 0; },
    call(fn, ...args) { return vm.runInContext(`(${fn}).apply(null, ${JSON.stringify(args)})`, ctx); },
  };
}

// ---------- F24a: no double-poll of the inspector ----------

test('polling: one 5s tick drives exactly one loadInspector call (no 2x duplicate)', async () => {
  const app = await makePollApp();
  app.set('inspectId', 's1');
  // Replace the real loadInspector with a counting stub.
  app.ctx.__liCount = 0;
  vm.runInContext('loadInspector = async () => { __liCount = __liCount + 1; };', app.ctx);
  // Simulate one 5s tick: fire every armed 5000ms interval callback.
  const five = app.intervals.filter(i => i.delay === 5000);
  assert.ok(five.length >= 1, 'expected at least one 5s poll interval');
  five.forEach(i => i.cb());
  for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r));
  assert.equal(app.ctx.__liCount, 1,
    `one 5s tick must produce exactly one loadInspector call (got ${app.ctx.__liCount} — the duplicate interval double-polled)`);
});

// ---------- F24b: refresh() in-flight guard ----------

test('refresh: a second call while the first is in flight is dropped (no 2x fetch burst)', async () => {
  const app = await makePollApp();
  let apiCalls = 0;
  let release;
  const gate = new Promise(r => { release = r; });
  app.setFetch(async (url) => {
    apiCalls++;
    await gate;
    return baseFetch(url);
  });
  // First refresh fires its 3 api() calls (synchronously, before the await).
  const p1 = app.call('refresh');
  assert.equal(apiCalls, 3, 'first refresh fired its 3 api() calls');
  // Second refresh while the first is in flight: the guard must drop it.
  const p2 = app.call('refresh');
  assert.equal(apiCalls, 3,
    `a second refresh while in flight must be dropped (got ${apiCalls} api() calls — expected 3, the old code fired 6)`);
  // Positive control: once the in-flight refresh settles, the next one fires.
  release();
  await p1; await p2;
  let again = 0;
  app.setFetch(async (url) => { again++; return baseFetch(url); });
  const p3 = app.call('refresh');
  await p3;
  assert.equal(again, 3, 'after the in-flight refresh settles, the guard clears and the next refresh fires again');
});

// ---------- F24c: layoutSparklines read/write ordering ----------

test('layoutSparklines: every layout read precedes every style write (no per-card reflow)', () => {
  const app = makeLayoutApp();
  app.activate();
  app.call('layoutSparklines');
  const ev = app.events;
  const lastRead = ev.lastIndexOf('read');
  const firstWrite = ev.indexOf('write');
  assert.ok(lastRead >= 0, 'expected at least one layout read (getComputedStyle / clientWidth)');
  assert.ok(firstWrite >= 0, 'expected at least one style write (bar height / width)');
  assert.ok(lastRead < firstWrite,
    `a style write happened before a later layout read (interleaved reflow). ` +
    `first write at index ${firstWrite}, last read at index ${lastRead} — the read pass must complete before any write`);
});
