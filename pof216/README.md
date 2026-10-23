# PoF2.16 — HTTPS Cookie/CHIPS and Opaque ESM Security Experiment

**SYNTHETIC ONLY, NOT PRODUCTION AUTHENTICATION.** Based on the previous verified PoF2.14 fixture. No changes to the main My-phone Studio.

- Three HTTPS loopback IP origins, ephemeral self-signed TLS key generated on the CI runner and immediately destroyed. Test browser ignores invalid TLS.
- Artifact A uses crossorigin=use-credentials for official Vite entry. Artifact B retains anonymous module entry.
- Chromium receives synthetic Secure, HttpOnly, SameSite=None, Partitioned cookies through Playwright. No actual user authentication/login is implemented.
- Every HTTP asset request requires the host-specific cookie; URL contains no token. The fixture deliberately uses ACAO:null with ACAC:true, to probe whether other sandboxed opaque-origin frames can read a private asset in the same browser.
- Test the React render, dynamic chunk, PNG, iframe sandbox, copied-URL denial in another browser, unauthorized opaque sibling fetch, anonymous module behavior, revocation, and a minimal offline Blob module.
- A green workflow means the experiment ran. Findings may be FAIL or CRITICAL_LEAK and still be valid scientific results. The JSON reports separate gate results.
- Public synthetic files only. No actual private source, credentials, user records, cloud deployment or billable service.

**PRIVATE PRODUCTION REMAINS NO-GO** until identity-bound authorization, safe opaque-origin CORS, cache/revocation and multiple browsers have passed.
