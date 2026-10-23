# PoF2.12 — Isolated Vite Multi-Chunk Preview (synthetic proof)

This is a **local-loopback, ephemeral GitHub Actions proof**. It neither modifies nor deploys My Phone Studio. The prior PoF2.9 Vite React fixture is recompiled using official Vite CLI with a fresh lockfile.

- Trusted host: 127.0.0.1, preview A: 127.0.0.2, preview B: 127.0.0.3. All are independent loopback sites and origins.
- Host sets frame-src; previews set header frame-ancestors and strict CSP; iframes use sandbox="allow-scripts" but never allow-same-origin.
- Static asset server: verified SHA-256 manifest, bounded resources, explicit MIME, only GET/HEAD, no backend, noncredentialed CORS for ESM and no external network.
- Playwright covers official Vite render, CSS/PNG, lazy-chunk HTTP 200, click, reload, origin and storage isolation, cross-session fetch/image denial, popup denial, unauthorized parent denial, mutated file refusal and session revocation.

**Scope boundary:** A passing test only validates this constrained local proof, not production multi-tenant security. There is NO per-user authorization, TLS, origin/subdomain provisioning, durable storage, untrusted ZIP parsing, full CPU/memory isolation or cloud service. Session URL secrecy is not access control. User source and private projects must not run here.

Workflow uses an existing public-repo GitHub Actions runner, synthetic files, read-only permissions and no deployments. Evidence is uploaded only to Actions artifacts.