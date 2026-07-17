# Documentation

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the system fits together and why: the multi-site honeypot model, the reverse proxy and its load-bearing routing/logging decisions, canary handling, the fingerprinting layers, the web app, and each research direction. |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Day-to-day work: prerequisites, every make target, running pieces directly, the two test suites, the verification loop, dependency layout, conventions, and the do-not-edit generated artifacts. |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Running the system on the public internet (EC2): sslip.io hostnames, `make set-public-host`, Let's Encrypt, the hardened public control center, monitoring, and the deployment checklist. |
| [AUTHENTICATION.md](AUTHENTICATION.md) | Setting up sign-in: secrets, approving emails, registration, optional TOTP two-factor, and troubleshooting. |
| [AI-Bot-Defender-Research-Roadmap.pdf](AI-Bot-Defender-Research-Roadmap.pdf) | The research roadmap the project's numbered directions (adversarial self-play, crawler intelligence, provenance, …) come from. LaTeX source alongside. |

Package-level READMEs live next to the code they describe:
[`crawler_graph/`](../crawler_graph/README.md),
[`querying/`](../querying/README.md),
[`selfplay/`](../selfplay/README.md),
[`template_generator/`](../template_generator/README.md),
[`testsuite/`](../testsuite/README.md), and the shorter ones in `app/`,
`auto_query/`, `website/`, `proxy/`, `ansible/`, `monitoring/`, and `scripts/`.
