import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { useLogger } from '~/composables/useLogger';
import { $fetch } from 'ofetch';
import { FETCH_TIMEOUT_MS } from '~~/server/lib/constants';
import type { CveMetadata, EpssSignal, ExploitEvidence, OsvAffectedPackage } from '~/types/secscore.types';
import type {
  ExploitDbRecord,
  HttpErrorLike,
  NvdConfigurationNode,
  NvdCve,
  NvdResponse,
  OsvResponse,
} from '~/types/fetchers.types';

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

    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const meta = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.error('nvd.fetch_failed', meta);
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

    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    const meta = {
      cveId,
      error: errorMessage,
      ...(isHttpErrorLike(error) ? { statusCode: error.statusCode } : {}),
    };
    logger.error('osv.fetch_failed', meta);
    return null;
  }
}
