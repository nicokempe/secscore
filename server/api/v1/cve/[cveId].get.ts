import { createError, defineEventHandler, getRouterParam, setResponseHeader } from 'h3';
import { isValidCve } from '~/utils/validators';
import { CACHE_TTL_MS, DEFAULT_RATE_LIMIT_PER_HOUR } from '~~/server/lib/constants';
import { fetchNvdMetadata } from '~~/server/lib/fetchers';
import { lruGet, lruSet } from '~~/server/lib/lru-cache';
import { applyPerIpRateLimit } from '~~/server/lib/rate-limit';
import { normalizeServerError } from '~~/server/lib/error-normalizer';
import type { CveMetadata } from '~/types/secscore.types';

const CACHE_CONTROL_HEADER = 'public, max-age=3600, stale-while-revalidate=86400';

export default defineEventHandler(async (event) => {
  try {
    const cveId: string = getRouterParam(event, 'cveId') ?? '';
    if (!isValidCve(cveId)) {
      throw createError({ statusCode: 400, statusMessage: 'Invalid CVE identifier' });
    }

    await applyPerIpRateLimit(event, { limitPerHour: DEFAULT_RATE_LIMIT_PER_HOUR });

    const cacheKey: string = `cve:${cveId}`;
    const cached = lruGet<CveMetadata>(cacheKey);
    if (cached) {
      setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
      return cached;
    }

    const metadata: CveMetadata = await fetchNvdMetadata(cveId);
    lruSet(cacheKey, metadata, CACHE_TTL_MS);

    setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
    return metadata;
  }
  catch (error) {
    const normalized = normalizeServerError(error);
    throw createError({ statusCode: normalized.statusCode, statusMessage: normalized.message });
  }
});

defineRouteMeta({
  openAPI: {
    operationId: 'getCveById',
    tags: ['Security Score'],
    summary: 'Get CVE metadata by ID',
    description:
      'Returns normalized CVE metadata for a given identifier (validated). '
      + 'Accepted format: CVE-YYYY-NNNN… (year is 1999–current; numeric part is 4–7 digits). '
      + 'Input length/pattern constraints are enforced server-side; since min/maxLength are not supported here, they are documented in this description. '
      + 'Responses are cached (LRU) and include `Cache-Control` headers for client/proxy caching.',
    parameters: [
      {
        in: 'path',
        name: 'cveId',
        required: true,
        schema: { type: 'string' },
        description:
          'CVE identifier to fetch. Pattern: `CVE-YYYY-NNNN+` (e.g., CVE-2024-12345). '
          + 'Validated using the server’s `isValidCve` rule.',
        example: 'CVE-2024-12345',
      },
    ],
    responses: {
      200: {
        description: 'CVE metadata found.',
        headers: {
          'Cache-Control': {
            description:
              'HTTP caching directives applied by the server (e.g., `public, max-age=3600, stale-while-revalidate=86400`).',
            schema: { type: 'string' },
          },
        },
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/CveMetadata' },
            examples: {
              example: {
                summary: 'Typical CVE metadata payload',
                value: {
                  id: 'CVE-2024-12345',
                  source: 'nvd',
                  published: '2024-06-12T09:30:00Z',
                  lastModified: '2024-06-20T14:05:00Z',
                  cvss: {
                    version: '3.1',
                    baseScore: 7.5,
                    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                  },
                  cwe: ['CWE-79'],
                  descriptions: [
                    { lang: 'en', value: 'Cross-site scripting in ...' },
                  ],
                  references: [
                    { url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345' },
                  ],
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
        description: 'CVE not found in upstream sources.',
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
          'Bad Gateway. Upstream source (e.g., NVD) failed or returned an unexpected response.',
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
