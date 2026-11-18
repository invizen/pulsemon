# pulsemon v1.1.16

## What's new

One fix: paused sensors keep their history across a restart.

### Fixed: paused sensors lose their history after a restart
At startup, only **active** sensors had their 24h probe history loaded into
memory. A paused sensor that was resumed later (the very likely sequence:
maintenance mode on → `pulsemon update --restart` → maintenance off) started
its in-memory series from empty — and nothing else ever re-loads a sensor's
history from the database. The result: blank 24h graphs, uptime that counted
only the probes since the resume, and an empty 60-probe inspector window,
while `/history` (which reads the database directly) still showed the data —
the two views disagreed.

`warmStats` now loads history for **active and paused** sensors at startup.
Memory per sensor is already capped (the raw tier holds at most the 1h window
or the last 60 probes, whichever is wider), so warming the extra sensors is
memory-safe.

## Verification
- Full `-race` on the release tree, zero data races, no failures.
- Dedicated regression test, sabotage-verified (fails when the query is
  reverted to active-only).
- Rationale: docs/DECISIONS.md → `warmstats-paused-sensors`.
