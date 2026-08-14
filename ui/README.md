# CIS Audit UI

React + Vite app that renders `report.json` — the output of
`audit_agent/report.py`'s `build_report()` (see `WORKPLAN.md` §2.2/§2.3).
Person B owns this directory.

## Contract

The only thing this app depends on is a static `GET /report.json`
returning:

```json
{
  "meta": { "target": "...", "timestamp": "...", "transport": "docker" },
  "summary": { "pass": 0, "fail": 0, "unknown": 0 },
  "fix_list": [ /* §2.3 shape, priority order */ ],
  "findings": [ /* §2.2 shape */ ],
  "unknowns": [ /* findings with status == UNKNOWN */ ]
}
```

`public/report.json` currently holds an empty placeholder matching this
shape. Person C's `cli.py` writes the real `report.json` after each run —
copy/symlink it into `public/report.json` so the dev server can serve it
(see `WORKPLAN.md` for where that hookup lives).

`src/App.jsx` is intentionally a thin placeholder (fetch + dump). **If the
team drops in an already-built UI instead, it only needs to honor the fetch
contract above** — nothing else in this directory is load-bearing.

## Run it

```bash
npm install   # already run once — rerun if package.json changes
npm run dev   # dev server, default http://localhost:5173
npm run build # production build to dist/, if needed for submission
```
