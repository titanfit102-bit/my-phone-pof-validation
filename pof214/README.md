# PoF2.14 — Per-request bearer capability vs private authorization

**Status:** SYNTHETIC EXPERIMENT, not a user-authenticated preview service. Branch \`feat/pof214-capability-authz-negative-proof\` extends the proven Vite fixture in the separate public validation repository. **My-phone is not modified.**

## What this actually proves
- Control plane mock grants each owner its own short-lived *session bearer URL*; different tenant/session IDs and distinct localhost origins.
- Each request for HTML/JS/ESM dynamic chunk/CSS/PNG requires a matching HMAC session capability in the **URL path**, session must be active and asset path must be in immutable SHA-256 manifest. The key is runtime-only and never committed.
- Cypress/Playwright-like Chromium browser proof exercises official \`vite build\`, clicks causing actual lazy chunk fetch, PNG/CSS, sandbox opaque origin, denial of unauthorized/foreign-session paths, revoke/expiry, SHA mutation, headers and no-store.
- Deliberately demonstrates **critical negative outcome**: a copied capability URL is replayable by an otherwise unauthenticated client. This is an expected test PASS of **observed vulnerability**, *not* private access protection.

## Strict NO-GO for private artifacts
Signed session URL is a bearer credential. An authenticated owner gate for minting cannot authenticate subsequent HTTP asset fetches. CSP/frame-ancestors do not protect against direct URL fetch. Session credential in URL may leak through server/intermediary logs, copied links and browser inspection. No browser identity proof, HTTPS, tenant access enforcement independent of the bearer, malicious ZIP handling, production worker isolation, deploy or cloud service is provided.

**Conclusion:** PoF2.14 can validate *capability-gated* static preview feasibility but **must not** be used for private/multi-tenant application source. Before continuing, select a safer per-resource identity-bound delivery design, then prove authenticated ESM imports in an opaque sandbox (or explicitly redesign trust boundary with user approval).

## Evidence
Only synthetic public fixture source. GitHub Actions read-only checkout with pinned GitHub Actions revisions, fresh Vite build, Chromium proof and SHA inventory; proof result JSON contains no bearer capabilities. No uploads, secrets or spending beyond standard public repository CI.