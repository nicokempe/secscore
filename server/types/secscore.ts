/**
 * Canonical CVE metadata merged from public sources (primarily NVD; OSV optional).
 */
export interface CveMetadata {
  /** CVE identifier, e.g. "CVE-2024-12345". */
  cveId: string
  /** Publication date in ISO8601 (from NVD when available), else null. */
  publishedDate: string | null
  /** Human-readable description from NVD (or null if unavailable). */
  description: string | null
  /** CVSS base score in [0..10] (v3.1 or v4, whichever is present), else null. */
  cvssBase: number | null
  /** CVSS vector string (e.g., "CVSS:3.1/AV:N/..."), else null. */
  cvssVector: string | null
  /** Raw CPE strings when present; an empty array if unavailable. */
  cpe: string[]
}

/** EPSS signal returned from FIRST (values in [0..1]). */
export interface EpssSignal {
  /** EPSS probability (0..1). */
  score: number
  /** EPSS percentile (0..1). */
  percentile: number
  /** ISO8601 timestamp when EPSS data was fetched. */
  fetchedAt: string
}

/** Evidence of a public exploit (from a local ExploitDB index file). */
export interface ExploitEvidence {
  /** Source of exploit evidence (currently only 'exploitdb'). */
  source: 'exploitdb'
  /** Canonical URL to the exploit entry; null if not resolvable. */
  url: string | null
  /** Exploit publication date in ISO8601; null if unknown. */
  publishedDate: string | null
}

/** Enriched, time-aware response for a CVE. */
export interface SecScoreResponse {
  /** CVE identifier tied to the enrichment response. */
  cveId: string
  /** CVE publication date in ISO8601 format. */
  publishedDate: string | null
  /** CVSS base score in the range [0..10]; null when unavailable. */
  cvssBase: number | null
  /** CVSS vector descriptor string; null when unavailable. */
  cvssVector: string | null
  /** Final time-aware SecScore in [0..10], clamped and rounded as per implementation. */
  secscore: number
  /** Asymmetric Laplace CDF probability (0..1) at current tWeeks. */
  exploitProb: number
  /** Category inferred from CPE/vendor/product (e.g., 'php', 'linux', 'windows', 'default'). */
  modelCategory: string
  /** Parameters used for the AL-CDF computation. */
  modelParams: { mu: number, lambda: number, kappa: number }
  /** EPSS signal if available; null otherwise. */
  epss: EpssSignal | null
  /** Array of public exploit evidence entries; empty if none. */
  exploits: ExploitEvidence[]
  /** True if CVE is in CISA KEV. */
  kev: boolean
  /** Human-readable reasons and provenance (kept short and actionable). */
  explanation: Array<{ title: string, detail: string, source: string }>
  /** ISO8601 timestamp when this response was computed. */
  computedAt: string
}
