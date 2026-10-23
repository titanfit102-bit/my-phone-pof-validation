# My Phone Expo Studio — isolated PoF2.9 validation

This public repository contains **synthetic Expo Web and Vite fixtures only** for proving official CLI builds and browser iframe behavior. It is separate from `titanfit102-bit/My-phone`.

The GitHub Actions workflow runs only on `main` and manual dispatch. It generates its own fixture lockfiles, runs official `vite build` and `expo export --platform web`, tests both artifacts with Playwright in browser iframes, and uploads evidence with SHA-256. GitHub Actions uses read-only permissions, a fixed Ubuntu runner and no project secrets, deploys or external service accounts.

Do not upload real projects, secrets, .env files or private source. This PoF is **not proof of support for arbitrary ZIP files, Android APK, Expo Router, or untrusted packages**. A passing PoF allows architectural review, not automatic merging or Production deployment.
