# pulsemon v1.2.2

## What's new

Two UI-fidelity commits since v1.2.1 — the inspector graph no longer
overstates single-packet losses, and seven QA-report polish items land
(empty state, theme flash, tab status, sub-millisecond readouts, cert
visibility, uptime labels). No Go changes, no DB schema changes.

### Inspector graph: hairline seam around loss ticks
- A single lost packet (one all-lost bucket in the 1h view) used to
  render as a ~2-interval void in the line — a 3/60-loss hour looked
  like four disconnected fragments, i.e. multi-minute outages.
- The line now extends flat to the MIDPOINT between its last point and
  the adjacent loss bucket: a hairline seam (half an interval per side)
  around each red tick. The 2026-10-24 no-bridging rule is preserved —
  the line never crosses or touches a null bucket.
- The area fill follows the extended ends.

### QA batch (7 items)
- **Empty state:** filtering out every sensor now offers a
  "Clear filters" button instead of the misleading "Add your first
  sensor".
- **Detail modal:** the MIN/AVG/MAX tile is compact (`12 / 29 / 60 ms`)
  so it no longer truncates; the full form stays in the tooltip.
- **Theme toggle:** no more dark-on-light flash — CSS transitions are
  blacked out for one frame during the toggle (the cards' transition
  classes used to crossfade every card through dark for ~150 ms).
- **Tab title + favicon:** the tab reads `(N ✕) pulsemon` while any
  active sensor is in error, and the favicon carries a red dot —
  trouble is visible from the taskbar without opening the window.
- **Sub-millisecond RTT:** LAN sensors reading 0.1–0.4 ms now display
  `<1 ms` instead of `0 ms` (which read like missing data). A true zero
  stays `0 ms`.
- **Cert expiry:** the detail modal always shows the TLS cert expiry
  for HTTPS sensors (date + days, colored by severity), not only
  inside 30 days. Cards keep the quiet warning-only note.
- **Uptime label:** the modal's uptime figure now carries its range —
  `98.33% uptime (1h)` — since the number follows the 1h/24h selector.

---
UI-only changes, gated by the node render harness (32 cases) +
`node --check` + live verification on zentest:9299.
