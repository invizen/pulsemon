# pulsemon v1.1.3

## What's new

### Fixed: sensor delete confirm could not be armed by clicking the trash icon
The outside-click disarm handler compared the event target after the button had
already been re-rendered into its armed state. Clicking the icon (the largest part
of the button) detached that element, so the handler saw "no armed button in the
click path" and instantly undid the arm — the icon never showed `CONFIRM?`.
Clicking the button's thin padding worked, which is why the bug looked random.
The handler now walks `event.composedPath()`, which is snapshotted at dispatch
time and is unaffected by the re-render. A source-level Go regression test
(`delete_confirm_test.go`) pins the fix in place.

### Fixed: table/cards view toggle and update re-check button did nothing
The static `data-args` attributes on those buttons were not valid JSON
(single-quoted / backslash-escaped), so the click dispatcher's `JSON.parse`
silently failed and the actions never fired. Rewritten as proper JSON with HTML
entities.

### Fixed: deferred poll render could swallow a click
When a 5-second poll render was deferred while a mouse button was held, the
deferred DOM swap could land before the browser delivered the `click` event.
The flush is now deferred by one tick (`setTimeout 0`) so `click` fires first.

### UI: easier-to-hit card controls, longer delete-confirm window
- Card action buttons (card and table views) enlarged (`p-1` → `p-1.5`, ~36px).
- Delete-confirm window extended 4s → 8s, with a larger `CONFIRM?` label and a
  "Click again to delete" tooltip while armed.

## Verification
- Reproduced the original failure with a real mouse click on the icon; verified
  the fix end-to-end (arm → survives poll re-render → second click → DELETE 204).
- Full `go test -race` suite green, `go vet` clean on linux + windows,
  `node --check` clean on all web JS.
