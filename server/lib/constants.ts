/**
 * Core configuration constants for the SecScore backend.
 * All values are documented with their intended usage.
 */

/**
 * Cache time-to-live in milliseconds for CVE metadata and enrichment responses (24 hours).
 */
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Maximum number of entries retained in the shared in-process LRU cache used by API responses.
 */
export const ENRICH_CACHE_MAX_ENTRIES = 2000;

/**
 * Maximum duration in milliseconds to await upstream HTTP responses when calling public APIs.
 */
export const FETCH_TIMEOUT_MS = 5000;

/**
 * Relative path to the asymmetric Laplace parameter JSON file bundled with the service.
 */
export const AL_PARAMS_FILE = 'model-params/al-params.json';

/**
 * CVSS v3.1 Exploit Code Maturity minimum factor ("Unproven").
 */
export const E_MIN_V31 = 0.91;

/**
 * CVSS v3.1 Exploit Code Maturity maximum factor ("High"/"Not Defined").
 */
export const E_MAX_V31 = 1.0;

/**
 * Weight applied to the asymmetric Laplace exploit probability when computing the SecScore temporal uplift.
 */
export const EXPLOITPROB_WEIGHT = 0.35;

/**
 * Maximum additive score bonus granted when public proof-of-concept exploits are available.
 */
export const POC_BONUS_MAX = 1.0;

/**
 * Weight factor converting EPSS probabilities into SecScore points (0..1 mapped to 0..2.5 in this configuration).
 */
export const EPSS_BLEND_WEIGHT = 2.5;

/**
 * Minimum SecScore enforced for CVEs listed in the CISA Known Exploited Vulnerabilities catalog.
 */
export const KEV_MIN_FLOOR = 8.0;
