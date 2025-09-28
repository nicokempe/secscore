import { randomUUID } from 'node:crypto';
import { createError, defineEventHandler, getRouterParam, setResponseHeader } from 'h3';
import { isValidCve } from '~/utils/validators';
import { CACHE_TTL_MS } from '~~/server/lib/constants';
import { normalizeServerError } from '~~/server/lib/error-normalizer';
import { fetchEpss, fetchNvdMetadata, fetchOsv, lookupExploitDb } from '~~/server/lib/fetchers';
import { readModelParams } from '~~/server/lib/model-params';
import { asymmetricLaplaceCdf, buildExplanation, computeSecScore, inferCategory } from '~~/server/lib/secscore-engine';
import { lruGet, lruSet } from '~~/server/lib/lru-cache';
import { getKevStatus, isInKev } from '~~/server/plugins/kev-loader';
import type { SecScoreResponse } from '~/types/secscore.types';

const CACHE_CONTROL_HEADER = 'public, max-age=3600, stale-while-revalidate=86400';
const MODEL_VERSION = '1';

export default defineEventHandler(async (event) => {
  const requestId = randomUUID();
  setResponseHeader(event, 'X-Request-Id', requestId);
  setResponseHeader(event, 'SecScore-Model-Version', MODEL_VERSION);
  try {
    const cveId = getRouterParam(event, 'cveId') ?? '';
    if (!isValidCve(cveId)) {
      throw createError({ statusCode: 400, statusMessage: 'Invalid CVE identifier' });
    }

    const cacheKey = `enrich:${cveId}`;
    const cached = lruGet<SecScoreResponse>(cacheKey);
    if (cached) {
      const payload = cached.modelVersion === MODEL_VERSION ? cached : { ...cached, modelVersion: MODEL_VERSION };
      if (payload !== cached) {
        lruSet(cacheKey, payload, CACHE_TTL_MS);
      }
      setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
      setResponseHeader(event, 'X-Cache', 'HIT');
      const latestKev = getKevStatus();
      if (latestKev.updatedAt) {
        setResponseHeader(event, 'X-KEV-Updated-At', latestKev.updatedAt);
      }
      return payload;
    }

    const [metadata, epss, osv] = await Promise.all([
      fetchNvdMetadata(cveId),
      fetchEpss(cveId),
      fetchOsv(cveId),
    ]);
    const kev = isInKev(cveId);
    const exploits = lookupExploitDb(cveId);

    const category = inferCategory(metadata.cpe);
    const modelParams = await readModelParams(category);

    const publishedDate = metadata.publishedDate ? Date.parse(metadata.publishedDate) : Number.NaN;
    const now = Date.now();
    const tWeeks = Number.isFinite(publishedDate) ? Math.max(0, (now - publishedDate) / (1000 * 60 * 60 * 24 * 7)) : 0;
    const exploitProbRaw = asymmetricLaplaceCdf(tWeeks, modelParams.mu, modelParams.lambda, modelParams.kappa);
    const exploitProb = Math.round(exploitProbRaw * 1000) / 1000;
    const hasExploit = exploits.length > 0;

    const secscore = computeSecScore({
      cvssBase: metadata.cvssBase,
      exploitProb,
      kev,
      hasExploit,
      epss,
    });

    const response: SecScoreResponse = {
      cveId,
      publishedDate: metadata.publishedDate,
      cvssBase: metadata.cvssBase,
      cvssVector: metadata.cvssVector,
      secscore,
      exploitProb,
      modelCategory: category,
      modelParams,
      epss,
      exploits,
      kev,
      osv,
      explanation: buildExplanation({
        kev,
        exploits,
        epss,
        exploitProb,
        modelCategory: category,
        modelParams,
        tWeeks,
        cvssBase: metadata.cvssBase,
        secscore,
      }),
      computedAt: new Date().toISOString(),
      modelVersion: MODEL_VERSION,
    };

    lruSet(cacheKey, response, CACHE_TTL_MS);
    setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
    setResponseHeader(event, 'X-Cache', 'MISS');
    const latestKev = getKevStatus();
    if (latestKev.updatedAt) {
      setResponseHeader(event, 'X-KEV-Updated-At', latestKev.updatedAt);
    }
    return response;
  }
  catch (error) {
    const normalized = normalizeServerError(error);
    throw createError({ statusCode: normalized.statusCode, statusMessage: normalized.message });
  }
});

/**
 * OpenAPI metadata for this route.
 * Must be placed at the bottom of the file.
 */
defineRouteMeta({
  openAPI: {
    operationId: 'enrichCveById',
    tags: ['Security Score'],
    summary: 'Enrich CVE with SecScore and public threat signals',
    description:
      'Computes a time-aware **SecScore** for the given CVE and returns an enriched payload combining:\n'
      + '- **NVD** metadata (CVSS base & vector, published date)\n'
      + '- **EPSS** likelihood\n'
      + '- **CISA KEV** inclusion flag\n'
      + '- **ExploitDB** lookup\n'
      + '- Model category & parameters used by the asymmetric Laplace CDF (μ, λ, κ)\n\n'
      + 'The `cveId` is strictly validated against the `CVE-YYYY-NNNN+` pattern (year 1999–current; numeric part ≥4 digits). '
      + 'Results are LRU-cached and responses include `Cache-Control` to enable client/proxy caching.',
    parameters: [
      {
        in: 'path',
        name: 'cveId',
        required: true,
        schema: { type: 'string' },
        description:
          'CVE identifier to enrich. Pattern: `CVE-YYYY-NNNN+` (e.g., `CVE-2024-12345`). '
          + 'Validated using the server-side `isValidCve` rule.',
        example: 'CVE-2024-12345',
      },
    ],
    responses: {
      200: {
        description:
          'Enriched CVE payload with SecScore, upstream signals (EPSS, KEV, ExploitDB), and model details.',
        headers: {
          'Cache-Control': {
            description:
              'HTTP caching directives applied by the server (e.g., `public, max-age=3600, stale-while-revalidate=86400`).',
            schema: { type: 'string' },
          },
        },
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/SecScoreResponse' },
            examples: {
              example: {
                summary: 'Typical enrichment result',
                value: {
                  cveId: 'CVE-2024-12345',
                  publishedDate: '2024-06-12T09:30:00Z',
                  cvssBase: 7.5,
                  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                  secscore: 0.81,
                  exploitProb: 0.63,
                  modelCategory: 'server_rce',
                  modelParams: { mu: 4.0, lambda: 0.45, kappa: 1.2 },
                  epss: 0.54,
                  kev: true,
                  exploits: [
                    {
                      id: 'EDB-123456',
                      source: 'exploitdb',
                      title: 'PoC exploit for CVE-2024-12345',
                      url: 'https://www.exploit-db.com/exploits/123456',
                      publishedDate: '2024-06-15T00:00:00Z',
                    },
                  ],
                  explanation:
                    'High SecScore due to KEV inclusion, available exploit(s), elevated EPSS, and recent publication. Model category server_rce with μ=4.0, λ=0.45, κ=1.2 produced exploit probability 0.63.',
                  computedAt: '2025-09-27T03:00:00Z',
                },
              },
            },
          },
        },
      },
      400: {
        description: 'Validation error. The provided CVE identifier is invalid.',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      404: {
        description:
          'CVE not found in upstream sources (e.g., NVD) or insufficient data to enrich.',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      429: {
        description:
          'Rate limit exceeded for the client IP (per-hour sliding window).',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      502: {
        description:
          'Bad Gateway. Upstream provider (NVD/EPSS/exploit source) failed or returned an unexpected response.',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      500: {
        description: 'Internal Server Error – unexpected failure.',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
    },
  },
});
