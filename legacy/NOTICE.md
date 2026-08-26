# Third-party backend notice

The files below `legacy/src/` and the original structure of `legacy/exploit.html`
come from [ArabPixel/WebKitty](https://github.com/ArabPixel/WebKitty) commit
`10846c6cf201d62f71d8374edc08d489331a6368`.

They are distributed under GNU AGPL-3.0-or-later. The complete license is in
`legacy/LICENSE`; the upstream README is in `legacy/UPSTREAM-README.md`.

Local modifications dated 2026-08-26 isolate the legacy backend below
`/legacy/`, select its exploit chain from the detected PS4 firmware, use the
root `payload.bin`, and share the root AppCache manifest.
