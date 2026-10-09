# v0.2.7

Sparkline rendering fix for high-DPI displays.

## Changes
- **Uniform bar widths on fractionally-scaled displays:** each sparkline bar is now
  rounded to a whole number of device pixels (via devicePixelRatio), eliminating the
  periodic "wide bar every Nth" beat pattern that appeared on 1.25x/1.5x scaled
  monitors.
- **Centered sparkline bars:** the 60-bar group is now horizontally centered in the
  container (justify-center), removing the right-side gap that accumulated from
  fixed-width bars in a wider container.
- **Resize listener:** layoutSparklines() re-runs on window resize (120ms
  debounce) so bars stay uniform at any card width.

UI-only change. No backend, API, or data changes.
