# pulsemon v1.1.2

Patch release for the dashboard.

## Fixed: intermittent dead clicks on sensor buttons (trash, pause, edit, clone)

The 5s background poll re-renders the sensor grid from scratch. When
that re-render landed in the few milliseconds between your mousedown
and mouseup, the browser never fired the click at all (a click needs
both events on the same DOM node) — so the button looked dead. Whether
a given click was swallowed was pure timing luck, which is why it
worked sometimes and not others.

Poll re-renders now defer while a mouse button is held and flush the
moment its released, so the node under your cursor cant be swapped
out mid-click. Verified in the browser: a re-render fired mid-press
no longer replaces the button, the deferred render runs on release,
and delete/pause flows are unaffected.

No backend changes.
