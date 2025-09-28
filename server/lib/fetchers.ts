import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { $fetch, type FetchOptions } from 'ofetch';
import { useLogger } from '~/composables/useLogger';
import { FETCH_TIMEOUT_MS, UPSTREAM_USER_AGENT } from '~~/server/lib/constants';
import type { CvssTemporalMultipliers, CveMetadata, EpssSignal, ExploitEvidence, OsvAffectedPackage } from '~/types/secscore.types';
import type {
  ExploitDbRecord,
  HttpErrorLike,
  NvdConfigurationNode,
  NvdCve,
  NvdCvssMetric,
  NvdResponse,
  OsvAffected,
  OsvEvent,
  OsvRange,
  OsvResponse,
} from '~/types/fetchers.types';
import type { Logger } from '~/types/logger.types';

const RETRY_ATTEMPTS = 2;
const RETRY_DELAY_MIN_MS = 200;
const RETRY_DELAY_MAX_MS = 400;

const COMMON_HEADERS: Record<string, string> = {
  'User-Agent': UPSTREAM_USER_AGENT,
  'Accept': 'application/json',
};

const CVSS_V3_RL_CODES: Record<string, number> = { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 };
const CVSS_V3_RL_TEXT: Record<string, number> = {
  NOT_DEFINED: 1,
  UNAVAILABLE: 1,
  WORKAROUND: 0.97,
  TEMPORARY: 0.96,
  OFFICIAL: 0.95,
};

const CVSS_V3_RC_CODES: Record<string, number> = { X: 1, C: 1, R: 0.96, U: 0.92 };
const CVSS_V3_RC_TEXT: Record<string, number> = {
  NOT_DEFINED: 1,
  CONFIRMED: 1,
  REASONABLE: 0.96,
  UNKNOWN: 0.92,
};

let exploitDbRecords: ExploitDbRecord[] | null = null;

/**
 * Narrows thrown values to the `HttpErrorLike` shape used across fetch helpers.
 *
 * @param value - Unknown error candidate emitted by upstream libraries.
 * @returns `true` when the value exposes numeric `statusCode` and string `message` fields.
 */
function isHttpErrorLike(value: unknown): value is HttpErrorLike {
  return (
    typeof value === 'object'
    && value !== null
    && 'statusCode' in value
    && 'message' in value
    && typeof (value as { statusCode: unknown }).statusCode === 'number'
    && typeof (value as { message: unknown }).message === 'string'
  );
}

/**
 * Provides a Promise-based delay helper to support retry backoff scheduling.
 *
 * @param ms - Duration in milliseconds to wait before resolving.
 */
async function delay(ms: number): Promise<void> {
  return new Promise(resolveDelay => setTimeout(resolveDelay, ms));
}

/**
 * Executes an asynchronous operation with bounded retries and jittered delays.
 *
 * @param operation - Function producing the Promise to evaluate.
 * @param retries - Maximum retry attempts before surfacing the latest error.
 * @returns Resolves with the operation result or rejects after exhausting retries.
 */
async function withRetries<T>(operation: () => Promise<T>, retries = RETRY_ATTEMPTS): Promise<T> {
  let attempt = 0;
  let lastError: unknown;
  while (attempt <= retries) {
    try {
      return await operation();
    }
    catch (error) {
      lastError = error;
      if (attempt === retries) {
        break;
      }
      const jitter = RETRY_DELAY_MIN_MS + Math.floor(Math.random() * (RETRY_DELAY_MAX_MS - RETRY_DELAY_MIN_MS + 1));
      await delay(jitter);
      attempt += 1;
    }
  }
  throw lastError;
}

/**
 * Ensures outgoing requests always include the service's standard headers.
 *
 * @param headers - Optional caller-supplied headers in any supported shape.
 * @returns A merged header collection containing upstream requirements.
 */
function normalizeHeaders(headers?: FetchOptions['headers']): FetchOptions['headers'] {
  if (!headers) {
    return COMMON_HEADERS;
  }
  if (Array.isArray(headers)) {
    return headers.concat(Object.entries(COMMON_HEADERS));
  }
  if (headers instanceof Headers) {
    const mergedHeaders = new Headers(headers);
    for (const [key, value] of Object.entries(COMMON_HEADERS)) {
      if (!mergedHeaders.has(key)) {
        mergedHeaders.set(key, value);
      }
    }
    return mergedHeaders;
  }
  return { ...COMMON_HEADERS, ...headers };
}

/**
 * Maps CVSS remediation level codes or text labels to temporal multipliers.
 *
 * @param value - Raw CVSS remediation level string from NVD payloads.
 * @returns Matching multiplier or `null` when the value cannot be resolved.
 */
function remediationMultiplierFromValue(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const normalized = value.toUpperCase();
  return CVSS_V3_RL_CODES[normalized] ?? CVSS_V3_RL_TEXT[normalized] ?? null;
}

/**
 * Maps CVSS report confidence codes or text labels to temporal multipliers.
 *
 * @param value - Raw CVSS report confidence string from NVD payloads.
 * @returns Matching multiplier or `null` when the value cannot be resolved.
 */
function reportConfidenceMultiplierFromValue(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const normalized = value.toUpperCase();
  return CVSS_V3_RC_CODES[normalized] ?? CVSS_V3_RC_TEXT[normalized] ?? null;
}

/**
 * Extracts the CVSS version from NVD metrics regardless of schema variant.
 *
 * @param cvssData - Metrics object that may include a `version` field.
 * @returns Parsed version string or `null` when unavailable.
 */
function extractCvssVersion(
  cvssData: NvdCvssMetric['cvssData'] | NvdCvssMetric['baseMetrics'] | undefined,
): string | null {
  if (!cvssData || typeof cvssData !== 'object') {
    return null;
  }
  if ('version' in cvssData) {
    const value = (cvssData as { version?: unknown }).version;
    return typeof value === 'string' ? value : null;
  }
  return null;
}

/**
 * Splits CVSS vector strings into their version prefix and component metrics.
 *
 * @param vector - CVSS vector string (e.g., `CVSS:3.1/AV:N/...`).
 * @returns Object containing the detected version and a key/value metric map.
 */
function parseCvssVector(vector: string | null): { version: string | null, metrics: Record<string, string> } {
  if (!vector) {
    return { version: null, metrics: {} };
  }
  const parts: string[] = vector.split('/');
  const prefix = parts.shift();
  let version: string | null = null;
  if (prefix?.startsWith('CVSS:')) {
    const segments: string[] = prefix.split(':');
    version = segments[1] ?? null;
  }
  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value) {
      metrics[key] = value;
    }
  }
  return { version, metrics };
}

/**
 * Resolves temporal multiplier values from CVSS metric data and vector strings.
 *
 * @param metric - Preferred metric entry retrieved from NVD.
 * @param vector - Raw CVSS vector string associated with the CVE.
 * @returns Temporal multiplier record with remediation and confidence weights.
 */
function deriveTemporalMultipliers(metric: NvdCvssMetric | undefined, vector: string | null): CvssTemporalMultipliers {
  const { metrics } = parseCvssVector(vector);
  const remediation = remediationMultiplierFromValue(metric?.remediationLevel)
    ?? remediationMultiplierFromValue(metrics.RL ?? metrics.R);
  const reportConfidence = reportConfidenceMultiplierFromValue(metric?.reportConfidence)
    ?? reportConfidenceMultiplierFromValue(metrics.RC);
  return {
    remediationLevel: remediation ?? null,
    reportConfidence: reportConfidence ?? null,
  };
}

/**
 * Picks the most relevant CVSS metric set from the mixed NVD response formats.
 *
 * @param cve - NVD vulnerability object containing multiple metric families.
 * @returns Selected metric data plus derived metadata for downstream use.
 */
function selectCvssMetric(cve: NvdCve): {
  metric: NvdCvssMetric | undefined
  vector: string | null
  baseScore: number | null
  version: string | null
  multipliers: CvssTemporalMultipliers
} {
  const metric = cve.metrics?.cvssMetricV40?.[0]
    ?? cve.metrics?.cvssMetricV31?.[0]
    ?? cve.metrics?.cvssMetricV30?.[0]
    ?? cve.metrics?.cvssMetricV3?.[0]
    ?? cve.metrics?.cvssMetricV2?.[0];

  const cvssData = metric?.cvssData ?? metric?.baseMetrics;
  const vectorString = typeof cvssData?.vectorString === 'string' ? cvssData.vectorString : null;
  const parsed = parseCvssVector(vectorString);
  const baseScoreCandidate = cvssData?.baseScore ?? cvssData?.score ?? null;
  const baseScore = typeof baseScoreCandidate === 'number' ? baseScoreCandidate : null;
  const multipliers: CvssTemporalMultipliers = deriveTemporalMultipliers(metric, vectorString);
  const version = extractCvssVersion(cvssData);

  return {
    metric,
    vector: vectorString,
    baseScore,
    version: version ?? parsed.version,
    multipliers,
  };
}

/**
 * Performs HTTP JSON requests with standardized headers, timeout, and retry logic.
 *
 * @param url - Absolute URL of the upstream API endpoint.
 * @param options - Fetch options forwarded to `ofetch`.
 * @returns Parsed JSON payload typed by the caller.
 */
async function fetchJson<T>(url: string, options: FetchOptions<'json'>): Promise<T> {
  const mergedHeaders = normalizeHeaders(options.headers);
  return withRetries(() => $fetch<T>(url, {
    ...options,
    headers: mergedHeaders,
    timeout: options.timeout ?? FETCH_TIMEOUT_MS,
    retry: 0,
  }));
}

/**
 * Fetches CVE metadata from the NVD v2 API and normalizes it into the service shape.
 */
export async function fetchNvdMetadata(cveId: string): Promise<CveMetadata> {
  const defaultMetadata: CveMetadata = {
    cveId,
    publishedDate: null,
    description: null,
    cvssBase: null,
    cvssVector: null,
    cvssVersion: null,
    temporalMultipliers: { remediationLevel: null, reportConfidence: null },
    cpe: [],
    modelVersion: '1',
  };

  try {
    const nvdResponse: NvdResponse = await fetchJson<NvdResponse>('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      method: 'GET',
      query: { cveId },
    });

    const matchingVulnerability = nvdResponse.vulnerabilities?.find(item => item.cve?.id === cveId)
      ?? nvdResponse.vulnerabilities?.[0];
    if (!matchingVulnerability?.cve) {
      const notFoundError: HttpErrorLike = {
        statusCode: 404,
        message: `CVE ${cveId} not found in NVD`,
      };
      throw notFoundError;
    }

    const nvdCve: NvdCve = matchingVulnerability.cve;
    const publishedDate = typeof nvdCve.published === 'string' ? nvdCve.published : null;
    const description = nvdCve.descriptions?.find(entry => entry.lang === 'en')?.value
      ?? nvdCve.descriptions?.[0]?.value
      ?? null;

    const selectedCvssMetric = selectCvssMetric(nvdCve);

    const cpeMatches: Set<string> = new Set<string>();
    const collectCpeFromNodes = (nodes?: NvdConfigurationNode[]): void => {
      if (!nodes) {
        return;
      }
      for (const node of nodes) {
        for (const match of node.cpeMatch ?? []) {
          if (typeof match.criteria === 'string') {
            cpeMatches.add(match.criteria);
          }
        }
        if (node.children) {
          collectCpeFromNodes(node.children);
        }
      }
    };
    collectCpeFromNodes(nvdCve.configurations?.nodes);

    return {
      cveId,
      publishedDate,
      description,
      cvssBase: selectedCvssMetric.baseScore,
      cvssVector: selectedCvssMetric.vector,
      cvssVersion: selectedCvssMetric.version ?? null,
      temporalMultipliers: selectedCvssMetric.multipliers,
      cpe: Array.from(cpeMatches),
      modelVersion: '1',
    };
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      throw error;
    }

    const logger: Logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const logMetadata = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.warn('nvd.fetch_failed', logMetadata);
    return defaultMetadata;
  }
}

/**
 * Fetches EPSS probability data; returns `null` when the upstream API is unreachable or the CVE is missing.
 */
export async function fetchEpss(cveId: string): Promise<EpssSignal | null> {
  try {
    const epssResponse = await fetchJson<{ data?: Array<{ cve?: string, epss?: string, percentile?: string }> }>('https://api.first.org/data/v1/epss', {
      method: 'GET',
      query: { cve: cveId },
    });

    const matchingRecord = epssResponse.data?.find(entry => entry.cve === cveId);
    if (!matchingRecord || matchingRecord.epss === undefined || matchingRecord.percentile === undefined) {
      return null;
    }

    const score: number = Number.parseFloat(matchingRecord.epss);
    const percentile: number = Number.parseFloat(matchingRecord.percentile);
    if (Number.isNaN(score) || Number.isNaN(percentile)) {
      return null;
    }

    return {
      score,
      percentile,
      fetchedAt: new Date().toISOString(),
    };
  }
  catch (error) {
    const logger: Logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('epss.fetch_failed', {
      cveId,
      error: errorMessage,
    });
    return null;
  }
}

/**
 * Lazily loads and caches the bundled ExploitDB index from disk.
 *
 * The parsed records are filtered to ensure each entry exposes a CVE identifier.
 */
function loadExploitDbIndex(): void {
  if (exploitDbRecords) {
    return;
  }
  try {
    const exploitIndexPath: string = resolve(process.cwd(), 'server/data/exploitdb-index.json');
    const exploitIndexContents: string = readFileSync(exploitIndexPath, 'utf8');
    const exploitDbPayload: ExploitDbRecord[] = JSON.parse(exploitIndexContents) as ExploitDbRecord[];
    exploitDbRecords = exploitDbPayload.filter(record => typeof record.cveId === 'string');
  }
  catch (error) {
    const logger: Logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('exploitdb.index_load_failed', {
      error: errorMessage,
    });
    exploitDbRecords = [];
  }
}

/**
 * Searches the bundled ExploitDB index for entries referencing the provided CVE identifier.
 */
export function lookupExploitDb(cveId: string): ExploitEvidence[] {
  loadExploitDbIndex();
  const normalizedCveId: string = cveId.toUpperCase();
  const matchingRecords: ExploitDbRecord[] = (exploitDbRecords ?? []).filter(record => record.cveId?.toUpperCase() === normalizedCveId);
  return matchingRecords.map<ExploitEvidence>(record => ({
    source: 'exploitdb',
    url: record.url ?? null,
    publishedDate: record.publishedDate ?? null,
  }));
}

/**
 * Converts an OSV event record into a normalized nullable-field structure.
 *
 * @param event - Raw OSV event describing introduction, fixes, or range limits.
 */
function normalizeOsvEvent(event: OsvEvent): { introduced: string | null, fixed: string | null, lastAffected: string | null, limit: string | null } {
  return {
    introduced: event.introduced ?? null,
    fixed: event.fixed ?? null,
    lastAffected: event.last_affected ?? null,
    limit: event.limit ?? null,
  };
}

/**
 * Normalizes OSV version range blocks for consistent downstream rendering.
 *
 * @param range - OSV range entry containing a type and associated events.
 */
function normalizeOsvRange(range: OsvRange): { type: string | null, events: Array<{ introduced: string | null, fixed: string | null, lastAffected: string | null, limit: string | null }> } {
  return {
    type: range.type ?? null,
    events: (range.events ?? []).map(normalizeOsvEvent),
  };
}

/**
 * Reshapes OSV affected package entries into the response contract expected by the API.
 *
 * @param entry - Raw affected package record returned by OSV.
 */
function normalizeOsvPackage(entry: OsvAffected): OsvAffectedPackage {
  const ranges = (entry.ranges ?? []).map(normalizeOsvRange);
  return {
    ecosystem: entry.package?.ecosystem ?? null,
    package: entry.package?.name ?? null,
    ranges: ranges.map(range => ({
      type: range.type,
      events: range.events.map(event => ({
        introduced: event.introduced,
        fixed: event.fixed,
        lastAffected: event.lastAffected,
        limit: event.limit,
      })),
    })),
  };
}

/**
 * Fetches affected package information from OSV for the provided CVE identifier.
 */
export async function fetchOsv(cveId: string): Promise<OsvAffectedPackage[] | null> {
  try {
    const osvResponse: OsvResponse = await fetchJson<OsvResponse>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`, {
      method: 'GET',
    });

    const normalizedPackages: OsvAffectedPackage[] = (osvResponse.affected ?? []).map(normalizeOsvPackage);

    return normalizedPackages.length > 0 ? normalizedPackages : null;
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      return null;
    }

    const logger: Logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const logMetadata = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.warn('osv.fetch_failed', logMetadata);
    return null;
  }
}
