# SecScore Nitro Backend

This directory hosts the Nitro server logic for the SecScore proof-of-concept. The implementation relies only on public data feeds and in-process memory structures (no database or Redis).

## Refreshing bundled datasets

### CISA Known Exploited Vulnerabilities (KEV)

The authoritative KEV feed is published by CISA at <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>. To update the local snapshot used by the server:

```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o server/data/kev.json
```

The health endpoint (`/api/health`) surfaces the `catalogVersion` and `dateReleased` fields so downstream systems can monitor dataset freshness.

### ExploitDB snapshot

`server/data/exploitdb-index.json` stores a curated subset of ExploitDB entries. Each item only needs three fields:

```json
{
  "cveId": "CVE-2017-0144",
  "url": "https://www.exploit-db.com/exploits/41738",
  "publishedDate": "2017-04-15T00:00:00Z"
}
```

To refresh the dataset, export the latest CVE-to-ExploitDB mappings from the upstream source (CSV export, API, or scraped feed), transform to the structure above, and overwrite the file. The backend reloads the snapshot at process start, so a restart is required to pick up changes.

## Tuning model parameters

The asymmetric Laplace parameters live in `model-params/al-params.json`. Adjust `{ mu, lambda, kappa }` per category (`default`, `php`, `linux`, `windows`, ...) to calibrate the time-aware exploit probability. After editing, restart the server to load the new values.



> **SecScore modelling summary (for implementers)**
> SecScore enhances CVSS by making the Threat/Temporal factor **time-aware** using an **Asymmetric Laplace CDF (AL-CDF)** fitted to real exploit timing data.
>
> **Inputs & idea**
>
> * Let `tWeeks` be the time since CVE publication, measured in **weeks** (floating-point).
> * For each broad category (e.g., `php`, `linux`, `windows`, `default`) use AL parameters `{ mu, lambda, kappa }` from `model-params/al-params.json`.
> * The **AL-CDF** gives `exploitProb ∈ [0,1]`: the probability an exploit exists or will exist soon at time `tWeeks`.
>
> **AL-CDF (use exactly this piecewise definition):**
> For parameters `{μ, λ, κ}` and time `t` (weeks):
>
> ```
> if t ≤ μ:
>   F(t; μ, λ, κ) = (κ^2 / (1 + κ^2)) * exp( (λ/κ) * (t - μ) )
> else:
>   F(t; μ, λ, κ) = 1 - (1 / (1 + κ^2)) * exp( -λ * κ * (t - μ) )
> ```
>
> Clamp numerically to `[0,1]`.
>
> **Map AL-CDF to an exploit-maturity factor E_S(t):**
> CVSS v3.1 uses an Exploit Code Maturity factor `E` with range `[E_min, E_max]`.
> In v3.1: `E_min = 0.91` (Unproven), `E_max = 1.00` (High/Not Defined).
> Convert as:
>
> ```
> E_S(t) = E_min + (E_max - E_min) * F(t; μ, λ, κ)
> ```
>
> **Use within CVSS logic (intuitive PoC mapping):**
>
> * Start from **CVSS Base** (B).
> * Replace/weight the Threat/Temporal multiplier `E` by `E_S(t)` to produce a **time-aware threat contribution**.
> * Blend additional public signals for prioritization:
    >
    >   * **CISA KEV** membership → strong floor/ceiling behavior (force high).
>   * **ExploitDB** public PoC → additive bounded bonus.
>   * **EPSS** value/percentile → small blend weight to nudge score.
> * Clamp final **SecScore** to `[0, 10]`.
> * Keep all coefficients/constants in code, documented and easy to tune.
