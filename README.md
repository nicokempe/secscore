[![SecScore GitHub Banner](./.github/media/banner.svg)](https://github.com/nicokempe/secscore)

## Description

This Security Score Proof of Concept is a lightweight Nuxt + Nitro web app that lets you paste any CVE ID and returns a time-aware threat score (SecScore) enriched with public signals (NVD, EPSS, CISA KEV, ExploitDB, OSV). After reading the paper [SecScore: Enhancing the CVSS Threat Metric Group with Empirical Evidences](https://arxiv.org/abs/2405.08539) and searching for an open, usable proof-of-concept I could not find one that matched the paper’s approach or my practical needs, so I decided to build this PoC to experiment with the model, combine it with real public feeds, and adapt the scoring and UX for realistic vulnerability prioritization. The project intentionally avoids a database (using Nitro caching and routeRules), exposes a simple UI and API, and keeps the model, parameters and evidence fully transparent for reproducible research and extension.

## Features

- 🔍 Enter any CVE ID and get an instant SecScore with current threat context
- 🌐 Powered only by public data sources: NVD, EPSS, CISA KEV, OSV, and ExploitDB
- ⚡ Lightweight design — no database, just Nitro caching and smart route rules
- 📊 Combines CVSS base metrics with exploit probability and real-world signals
- 📝 Transparent explanations show why a CVE is prioritized (PoC found, KEV flag, EPSS score)
- 🎨 Clean and intuitive Nuxt frontend for quick lookups and demos
- 🧩 Fully open-source, easy to extend with additional APIs or custom scoring logic

## License

This project is licensed under the [Apache License](https://github.com/nicokempe/secscore/blob/main/LICENSE).
