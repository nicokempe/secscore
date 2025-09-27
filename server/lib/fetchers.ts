import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { $fetch } from 'ofetch';
import { FETCH_TIMEOUT_MS } from '~~/server/lib/constants';
import type { CveMetadata, EpssSignal, ExploitEvidence, OsvAffectedPackage } from '~/types/secscore.types';

interface NvdDescription {
  lang?: string
  value?: string
}

interface NvdCvssData {
  baseScore?: number
  vectorString?: string
  score?: number
}

interface NvdCvssMetric {
  cvssData?: NvdCvssData
  baseMetrics?: { baseScore?: number, score?: number, vectorString?: string }
}

interface NvdCpeMatch {
  criteria?: string
}

interface NvdConfigurationNode {
  cpeMatch?: NvdCpeMatch[]
  children?: NvdConfigurationNode[]
}

interface NvdCve {
  id?: string
  published?: string
  descriptions?: NvdDescription[]
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[]
    cvssMetricV30?: NvdCvssMetric[]
    cvssMetricV3?: NvdCvssMetric[]
    cvssMetricV40?: NvdCvssMetric[]
    cvssMetricV2?: NvdCvssMetric[]
  }
  configurations?: { nodes?: NvdConfigurationNode[] }
}

interface NvdVulnerability {
  cve?: NvdCve
}

interface NvdResponse {
  vulnerabilities?: NvdVulnerability[]
}

interface KevEntry {
  cveID?: string
}

interface KevFile {
  vulnerabilities?: KevEntry[]
  catalogVersion?: string
  dateReleased?: string
}

interface ExploitDbRecord {
  url?: string
  publishedDate?: string
  cveId?: string
}

let kevLoaded = false;
const kevSet = new Set<string>();
let exploitDbRecords: ExploitDbRecord[] | null = null;
let kevMetadata: { catalogVersion: string | null, dateReleased: string | null } = {
  catalogVersion: null,
  dateReleased: null,
};

interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
  limit?: string
}

interface OsvRange {
  type?: string
  events?: OsvEvent[]
}

interface OsvPackage {
  ecosystem?: string
  name?: string
}

interface OsvAffected {
  package?: OsvPackage
  ranges?: OsvRange[]
}

interface OsvResponse {
  affected?: OsvAffected[]
}

interface HttpErrorLike {
  statusCode: number
  message: string
}

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
 * Fetches CVE metadata from the NVD v2 API and normalizes it into the service shape.
 */
export async function fetchNvdMetadata(cveId: string): Promise<CveMetadata> {
  const defaultMetadata: CveMetadata = {
    cveId,
    publishedDate: null,
    description: null,
    cvssBase: null,
    cvssVector: null,
    cpe: [],
    modelVersion: '1',
  };

  try {
    const response: NvdResponse = await $fetch<NvdResponse>('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      query: { cveId },
      retry: 2,
      timeout: FETCH_TIMEOUT_MS,
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

    const cvssData
      = cve.metrics?.cvssMetricV31?.[0]?.cvssData
        || cve.metrics?.cvssMetricV40?.[0]?.cvssData
        || cve.metrics?.cvssMetricV30?.[0]?.cvssData
        || cve.metrics?.cvssMetricV3?.[0]?.cvssData
        || cve.metrics?.cvssMetricV2?.[0]?.baseMetrics;

    const baseScoreCandidate = cvssData?.baseScore ?? cvssData?.score ?? null;
    const cvssBase = typeof baseScoreCandidate === 'number' ? baseScoreCandidate : null;
    const cvssVector = typeof cvssData?.vectorString === 'string' ? cvssData.vectorString : null;

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
      cvssBase,
      cvssVector,
      cpe: Array.from(cpeSet),
      modelVersion: '1',
    };
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      throw error;
    }

    console.log(
      JSON.stringify({
        time: new Date().toISOString(),
        level: 'error',
        msg: 'Failed to fetch NVD metadata',
        errorType: 'NvdFetchError',
        context: { cveId, error: error instanceof Error ? error.message : String(error) },
      }),
    );
    return defaultMetadata;
  }
}

/**
 * Fetches EPSS probability data; returns `null` when the upstream API is unreachable or the CVE is missing.
 */
export async function fetchEpss(cveId: string): Promise<EpssSignal | null> {
  try {
    const response = await $fetch<{ data?: Array<{ cve?: string, epss?: string, percentile?: string }> }>('https://api.first.org/data/v1/epss', {
      query: { cve: cveId },
      retry: 2,
      timeout: FETCH_TIMEOUT_MS,
    });

    const record = response.data?.find(entry => entry.cve === cveId);
    if (!record || record.epss === undefined || record.percentile === undefined) {
      return null;
    }

    const score = Number.parseFloat(record.epss);
    const percentile = Number.parseFloat(record.percentile);
    if (Number.isNaN(score) || Number.isNaN(percentile)) {
      return null;
    }

    return {
      score,
      percentile,
      fetchedAt: new Date().toISOString(),
    };
  }
  catch {
    return null;
  }
}

/**
 * Loads the local CISA KEV JSON file (if present) and populates an in-memory lookup set.
 */
export async function loadKevIndex(): Promise<void> {
  if (kevLoaded) {
    return;
  }

  try {
    const { readFile } = await import('node:fs/promises');
    const kevPath = resolve(process.cwd(), 'server/data/kev.json');
    const file = await readFile(kevPath, 'utf8');
    const parsed = JSON.parse(file) as KevFile;
    for (const entry of parsed.vulnerabilities ?? []) {
      if (entry.cveID) {
        kevSet.add(entry.cveID);
      }
    }
    kevMetadata = {
      catalogVersion: typeof parsed.catalogVersion === 'string' ? parsed.catalogVersion : null,
      dateReleased: typeof parsed.dateReleased === 'string' ? parsed.dateReleased : null,
    };
  }
  catch {
    // Intentionally ignore missing or malformed KEV files.
    kevMetadata = { catalogVersion: null, dateReleased: null };
  }
  finally {
    kevLoaded = true;
  }
}

/**
 * Returns whether a CVE is present in the loaded KEV index.
 */
export function isInKev(cveId: string): boolean {
  return kevSet.has(cveId);
}

/**
 * Exposes KEV dataset metadata (catalog version + release timestamp) after loading.
 */
export function getKevMetadata(): { catalogVersion: string | null, dateReleased: string | null } {
  return kevMetadata;
}

function loadExploitDbIndex(): void {
  if (exploitDbRecords) {
    return;
  }
  try {
    const filePath = resolve(process.cwd(), 'server/data/exploitdb-index.json');
    const fileContents = readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(fileContents) as ExploitDbRecord[];
    exploitDbRecords = parsed.filter(record => typeof record.cveId === 'string');
  }
  catch {
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

/**
 * Fetches affected package information from OSV for the provided CVE identifier.
 */
export async function fetchOsv(cveId: string): Promise<OsvAffectedPackage[] | null> {
  try {
    const response = await $fetch<OsvResponse>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`, {
      retry: 2,
      timeout: FETCH_TIMEOUT_MS,
    });

    const affectedPackages = response.affected?.map<OsvAffectedPackage>(entry => ({
      ecosystem: entry.package?.ecosystem ?? null,
      package: entry.package?.name ?? null,
      ranges: (entry.ranges ?? []).map(range => ({
        type: range.type ?? null,
        events: (range.events ?? []).map(event => ({
          introduced: event.introduced ?? null,
          fixed: event.fixed ?? null,
          lastAffected: event.last_affected ?? null,
          limit: event.limit ?? null,
        })),
      })),
    })) ?? [];

    return affectedPackages.length > 0 ? affectedPackages : null;
  }
  catch (error) {
    if (isHttpErrorLike(error) && error.statusCode === 404) {
      return null;
    }

    console.log(
      JSON.stringify({
        time: new Date().toISOString(),
        level: 'error',
        msg: 'Failed to fetch OSV data',
        errorType: 'OsvFetchError',
        context: { cveId, error: error instanceof Error ? error.message : String(error) },
      }),
    );
    return null;
  }
}
