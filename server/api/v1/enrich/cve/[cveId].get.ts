import { randomUUID } from 'node:crypto';
import { createError, defineEventHandler, getHeader, getRouterParam, setResponseHeader } from 'h3';
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
    const cveId: string = getRouterParam(event, 'cveId') ?? '';
    if (!isValidCve(cveId)) {
      throw createError({ statusCode: 400, statusMessage: 'Invalid CVE identifier' });
    }

    const runtimeConfig = useRuntimeConfig(event);
    const shouldVerifyTurnstile: boolean = Boolean(runtimeConfig.turnstile?.enabled && runtimeConfig.turnstile.secretKey);
    if (shouldVerifyTurnstile) {
      const token = getHeader(event, 'cf-turnstile-response');
      if (!token) {
        throw createError({ statusCode: 400, statusMessage: 'Turnstile verification required' });
      }

      const verification = await verifyTurnstileToken(token, event);
      if (!verification.success) {
        throw createError({
          statusCode: 403,
          statusMessage: 'Turnstile verification failed',
          data: { errors: verification['error-codes'] ?? [] },
        });
      }
    }

    const cacheKey: string = `enrich:${cveId}`;
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
    const exploitProb = asymmetricLaplaceCdf(tWeeks, modelParams.mu, modelParams.lambda, modelParams.kappa);
    const hasExploit = exploits.length > 0;

    const secscoreComputation = computeSecScore({
      cvssBase: metadata.cvssBase,
      cvssVector: metadata.cvssVector,
      cvssVersion: metadata.cvssVersion,
      exploitProb,
      kev,
      hasExploit,
      epss,
      temporalMultipliers: metadata.temporalMultipliers,
    });

    const secscore = secscoreComputation.secscore;

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
        temporalKernel: secscoreComputation.temporalKernel,
        temporalExploitMaturity: secscoreComputation.exploitMaturity,
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
      + '- **OSV** affected package breakdown (if available)\n'
      + '- Model category & parameters used by the asymmetric Laplace CDF (μ, λ, κ)\n\n'
      + 'The `cveId` must match the `CVE-YYYY-NNNN+` pattern (year 1999–current; numeric part ≥ 4 digits). '
      + 'Requests are validated server-side, cached (LRU), and respond with cache metadata headers.',
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
          'X-Request-Id': {
            description: 'Unique identifier assigned to the request for tracing/log correlation.',
            schema: { type: 'string', format: 'uuid' },
          },
          'X-Cache': {
            description: 'Cache hit metadata (`HIT` or `MISS`).',
            schema: { type: 'string', enum: ['HIT', 'MISS'] },
          },
          'SecScore-Model-Version': {
            description: 'Model version embedded in the response payload.',
            schema: { type: 'string' },
          },
          'X-KEV-Updated-At': {
            description: 'Timestamp (ISO8601) of the latest KEV dataset available to the service (header omitted if unknown).',
            schema: { type: 'string', format: 'date-time' },
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
                  secscore: 8.1,
                  exploitProb: 0.63,
                  modelCategory: 'windows',
                  modelParams: { mu: 4.0, lambda: 0.45, kappa: 1.2 },
                  epss: {
                    score: 0.54,
                    percentile: 0.92,
                    fetchedAt: '2024-06-20T12:00:00Z',
                  },
                  kev: true,
                  exploits: [
                    {
                      source: 'exploitdb',
                      url: 'https://www.exploit-db.com/exploits/123456',
                      publishedDate: '2024-06-15T00:00:00Z',
                    },
                  ],
                  osv: [
                    {
                      ecosystem: 'npm',
                      package: 'examplecms',
                      ranges: [
                        {
                          type: 'SEMVER',
                          events: [
                            {
                              introduced: '1.0.0',
                              fixed: '1.2.0',
                              lastAffected: null,
                              limit: '< 1.2.0',
                            },
                          ],
                        },
                      ],
                    },
                  ],
                  explanation: [
                    { title: 'CISA KEV', detail: 'Listed by CISA KEV', source: 'cisa-kev' },
                    { title: 'Exploit PoC', detail: 'ExploitDB entry from 2024-06-15', source: 'exploitdb' },
                    { title: 'EPSS', detail: 'EPSS=0.54 (p92)', source: 'epss' },
                    {
                      title: 'Time-aware',
                      detail:
                        'AL-CDF exploitProb=0.630 at tWeeks=1.0 for category=windows (mu=4.00, lambda=0.45, kappa=1.20)',
                      source: 'secscore',
                    },
                    { title: 'CVSS Base', detail: 'CVSS base score 7.5', source: 'cvss' },
                    { title: 'SecScore', detail: 'Final SecScore 8.1', source: 'secscore' },
                  ],
                  computedAt: '2024-06-20T12:34:56.000Z',
                  modelVersion: '1',
                },
              },
            },
          },
        },
      },
      400: {
        description: 'Validation error (e.g., malformed CVE identifier or missing Turnstile token).',
        content: {
          'application/json': { schema: { $ref: '#/components/schemas/Error' } },
        },
      },
      403: {
        description: 'Turnstile verification failed.',
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
