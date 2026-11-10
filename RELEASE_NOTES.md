# pulsemon v1.1.1

Patch release for the dashboard.

## Fixed: stuck "CONFIRM?" on sensor delete

The delete button uses a two-click confirm: click the trash icon, the
button flips to "CONFIRM?" for 4 seconds, click it again to delete.
When the 4 seconds expired (or you clicked elsewhere), the logical
state cleared but the button stayed painted "CONFIRM?" until the next
5s poll re-rendered — and clicking that stuck button did nothing, so
the delete appeared broken.

The disarm now resets the button back to the trash icon, so the visual
state always matches the armed state. Verified end-to-end in the
browser: arm → timer expiry → icon restored → re-arm → delete.

No backend changes — the delete API path was never affected.
