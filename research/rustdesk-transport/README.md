# RustDesk transport research

Evaluating whether RustDesk's rendezvous + relay infrastructure can replace the
Cloudflare Tunnel in T3 Connect, and how to make that change without building a
generic plugin runtime.

- **[`plan.html`](./plan.html)** — the plan: architecture analysis, three premise
  corrections, the plugin-system vs direct-modification comparison, and the
  phased implementation plan. Open it in a browser.
- **[`evidence.md`](./evidence.md)** — the evidence log behind the plan. Every
  claim cited to `path:line` in the upstream repos.
- **[`poc/probe.py`](./poc/probe.py)** — a standard-library-only probe that
  speaks the RustDesk rendezvous wire protocol. It reaches the live public
  server's signed key-exchange handshake, which is the first thing a
  third-party client must implement.

## Status

| Phase | Description | State |
|---|---|---|
| 0 | Protocol spike + server/licence decisions | in progress |
| 1 | Make the 3-machine cap configurable | not started |
| 2 | Extract the transport contract and connector registry | not started |
| 3 | RustDesk transport (connector pair + provider) | not started |
| 4 | Client runtime transport session | not started |
| 5 | Remote control (separate project) | not started |

Phases 0 and 1 are worth doing regardless of whether the RustDesk transport
ever ships.
