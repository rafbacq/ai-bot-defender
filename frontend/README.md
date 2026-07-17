# `frontend/` — Tailwind CSS build for the web app

Not an application — just the Node toolchain that compiles the app's utility
CSS. `make app` runs it automatically (via the `frontend-css` target) whenever
a template or one of these inputs changed:

- `tailwind.input.css` — the source sheet.
- `tailwind.config.js` — scans `app/templates/*.html` for used classes.

Output is `app/static/css/tailwind.css`, which is **tracked** so production
machines never need Node at runtime. Don't edit the output by hand; edit the
input files and rerun `make frontend-css`.
