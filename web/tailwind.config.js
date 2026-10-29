// Tailwind build config for pulsemon's precompiled dashboard CSS.
//
// This REPLACES the in-browser Play CDN JIT (which used to be vendored as
// web/vendor/tailwind.js) with a static, build-time-compiled stylesheet.
// The theme extension mirrors the `tailwind.config` block that used to live
// inline in web/index.html: colors are CSS-variable-driven
// (rgb(var(--x)/<alpha-value>)) so the light/dark theme swap (the .light
// class in web/styles.css) keeps working with a single compiled stylesheet.
//
// Build: `make css` (see the Makefile) — runs the Tailwind CLI against
// web/tailwind.input.css and writes web/vendor/tailwind.css. Regenerate
// whenever you add or rename a Tailwind class in index.html / app.js.
//
// content: the files scanned for class names. index.html carries the markup;
// app.js carries the JS that composes class strings (status badges, etc.).
// The CLI scans raw source text, so full class literals in JS strings are
// picked up; the safelist below is belt-and-suspenders for the status-color
// utilities (ok/warn/bad, with /alpha variants) composed in app.js.
// __dirname keeps the paths anchored to this config's folder (web/) no matter
// where the CLI is invoked from (the Makefile runs it from the repo root).
const path = require('path');
module.exports = {
  content: [path.resolve(__dirname, 'index.html'), path.resolve(__dirname, 'app.js')],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        surface: {
          950: 'rgb(var(--s950)/<alpha-value>)',
          900: 'rgb(var(--s900)/<alpha-value>)',
          850: 'rgb(var(--s850)/<alpha-value>)',
          800: 'rgb(var(--s800)/<alpha-value>)',
          700: 'rgb(var(--s700)/<alpha-value>)',
          600: 'rgb(var(--s600)/<alpha-value>)',
        },
        ok: 'rgb(var(--okc)/<alpha-value>)',
        warn: 'rgb(var(--warnc)/<alpha-value>)',
        bad: 'rgb(var(--badc)/<alpha-value>)',
        jit: 'rgb(var(--jitc)/<alpha-value>)',
      },
    },
  },
  safelist: [
    { pattern: /^(bg|text|border)-(ok|warn|bad)(\/\d{1,2})?$/ },
  ],
  // No plugins. Core utilities only — the dashboard uses stock Tailwind.
};
