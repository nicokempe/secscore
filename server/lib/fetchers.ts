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

async function delay(ms: number): Promise<void> {
  return new Promise(resolveDelay => setTimeout(resolveDelay, ms));
}

async function withRetries<T>(fn: () => Promise<T>, retries = RETRY_ATTEMPTS): Promise<T> {
  let attempt = 0;
  let lastError: unknown;
  while (attempt <= retries) {
    try {
      return await fn();
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

function normalizeHeaders(headers?: FetchOptions['headers']): FetchOptions['headers'] {
  if (!headers) {
    return COMMON_HEADERS;
  }
  if (Array.isArray(headers)) {
    return headers.concat(Object.entries(COMMON_HEADERS));
  }
  if (headers instanceof Headers) {
    const merged = new Headers(headers);
    for (const [key, value] of Object.entries(COMMON_HEADERS)) {
      if (!merged.has(key)) {
        merged.set(key, value);
      }
    }
    return merged;
  }
  return { ...COMMON_HEADERS, ...headers };
}

function remediationMultiplierFromValue(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const normalized = value.toUpperCase();
  return CVSS_V3_RL_CODES[normalized] ?? CVSS_V3_RL_TEXT[normalized] ?? null;
}

function reportConfidenceMultiplierFromValue(value: string | undefined): number | null {
  if (!value) {
    return null;
  }
  const normalized = value.toUpperCase();
  return CVSS_V3_RC_CODES[normalized] ?? CVSS_V3_RC_TEXT[normalized] ?? null;
}

function parseCvssVector(vector: string | null): { version: string | null, metrics: Record<string, string> } {
  if (!vector) {
    return { version: null, metrics: {} };
  }
  const parts = vector.split('/');
  const prefix = parts.shift();
  let version: string | null = null;
  if (prefix?.startsWith('CVSS:')) {
    const segments = prefix.split(':');
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
  const multipliers = deriveTemporalMultipliers(metric, vectorString);

  return {
    metric,
    vector: vectorString,
    baseScore,
    version: cvssData?.version ?? parsed.version,
    multipliers,
  };
}

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
    const response = await fetchJson<NvdResponse>('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      method: 'GET',
      query: { cveId },
    });

    const vulnerability = response.vulnerabilities?.find(item => item.cve?.id === cveId) ?? response.vulnerabilities?.[0];
    if (!vulnerability?.cve) {
      const notFoundError: HttpErrorLike = {
        statusCode: 404,
        message: `CVE ${cveId} not found in NVD`,
      };
      throw notFoundError;
    }

    const cve: NvdCve = vulnerability.cve;
    const publishedDate = typeof cve.published === 'string' ? cve.published : null;
    const description = cve.descriptions?.find(entry => entry.lang === 'en')?.value ?? cve.descriptions?.[0]?.value ?? null;

    const selected = selectCvssMetric(cve);

    const cpeSet: Set<string> = new Set<string>();
    const collectCpe = (nodes?: NvdConfigurationNode[]): void => {
      if (!nodes) {
        return;
      }
      for (const node of nodes) {
        for (const match of node.cpeMatch ?? []) {
          if (typeof match.criteria === 'string') {
            cpeSet.add(match.criteria);
          }
        }
        if (node.children) {
          collectCpe(node.children);
        }
      }
    };
    collectCpe(cve.configurations?.nodes);

    return {
      cveId,
      publishedDate,
      description,
      cvssBase: selected.baseScore,
      cvssVector: selected.vector,
      cvssVersion: selected.version ?? null,
      temporalMultipliers: selected.multipliers,
      cpe: Array.from(cpeSet),
      modelVersion: '1',
    };
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      throw error;
    }

    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const meta = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.warn('nvd.fetch_failed', meta);
    return defaultMetadata;
  }
}

/**
 * Fetches EPSS probability data; returns `null` when the upstream API is unreachable or the CVE is missing.
 */
export async function fetchEpss(cveId: string): Promise<EpssSignal | null> {
  try {
    const response = await fetchJson<{ data?: Array<{ cve?: string, epss?: string, percentile?: string }> }>('https://api.first.org/data/v1/epss', {
      method: 'GET',
      query: { cve: cveId },
    });

    const record = response.data?.find(entry => entry.cve === cveId);
    if (!record || record.epss === undefined || record.percentile === undefined) {
      return null;
    }

    const score: number = Number.parseFloat(record.epss);
    const percentile: number = Number.parseFloat(record.percentile);
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
    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('epss.fetch_failed', {
      cveId,
      error: errorMessage,
    });
    return null;
  }
}

function loadExploitDbIndex(): void {
  if (exploitDbRecords) {
    return;
  }
  try {
    const filePath: string = resolve(process.cwd(), 'server/data/exploitdb-index.json');
    const fileContents: string = readFileSync(filePath, 'utf8');
    const parsed: ExploitDbRecord[] = JSON.parse(fileContents) as ExploitDbRecord[];
    exploitDbRecords = parsed.filter(record => typeof record.cveId === 'string');
  }
  catch (error) {
    const logger = useLogger();
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
  const target = cveId.toUpperCase();
  const matches = (exploitDbRecords ?? []).filter(record => record.cveId?.toUpperCase() === target);
  return matches.map<ExploitEvidence>(record => ({
    source: 'exploitdb',
    url: record.url ?? null,
    publishedDate: record.publishedDate ?? null,
  }));
}

function normalizeOsvEvent(event: OsvEvent): { introduced: string | null, fixed: string | null, lastAffected: string | null, limit: string | null } {
  return {
    introduced: event.introduced ?? null,
    fixed: event.fixed ?? null,
    lastAffected: event.last_affected ?? null,
    limit: event.limit ?? null,
  };
}

function normalizeOsvRange(range: OsvRange): { type: string | null, events: Array<{ introduced: string | null, fixed: string | null, lastAffected: string | null, limit: string | null }> } {
  return {
    type: range.type ?? null,
    events: (range.events ?? []).map(normalizeOsvEvent),
  };
}

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
    const response = await fetchJson<OsvResponse>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`, {
      method: 'GET',
    });

    const affectedPackages = (response.affected ?? []).map(normalizeOsvPackage);

    return affectedPackages.length > 0 ? affectedPackages : null;
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      return null;
    }

    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const meta = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.warn('osv.fetch_failed', meta);
    return null;
  }
}
