import { randomUUID } from 'node:crypto';
import { createError, defineEventHandler, getRouterParam, setResponseHeader } from 'h3';
import { isValidCve } from '~/utils/validators';
import { CACHE_TTL_MS } from '~~/server/lib/constants';
import { fetchNvdMetadata } from '~~/server/lib/fetchers';
import { lruGet, lruSet } from '~~/server/lib/lru-cache';
import { normalizeServerError } from '~~/server/lib/error-normalizer';
import type { CveMetadata } from '~/types/secscore.types';

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

    const cacheKey: string = `cve:${cveId}`;
    const cached = lruGet<CveMetadata>(cacheKey);
    if (cached) {
      const payload = cached.modelVersion === MODEL_VERSION ? cached : { ...cached, modelVersion: MODEL_VERSION };
      if (payload !== cached) {
        lruSet(cacheKey, payload, CACHE_TTL_MS);
      }
      setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
      setResponseHeader(event, 'X-Cache', 'HIT');
      return payload;
    }

    const metadata: CveMetadata = await fetchNvdMetadata(cveId);
    const responsePayload: CveMetadata = { ...metadata, modelVersion: MODEL_VERSION };
    lruSet(cacheKey, responsePayload, CACHE_TTL_MS);

    setResponseHeader(event, 'Cache-Control', CACHE_CONTROL_HEADER);
    setResponseHeader(event, 'X-Cache', 'MISS');
    return responsePayload;
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
      'Returns normalized CVE metadata sourced from NVD. '
      + 'The identifier must match `CVE-YYYY-NNNN+` (year 1999–current; numeric portion ≥ 4 digits). '
      + 'Pattern validation happens server-side to protect upstream services. '
      + 'Responses are cached (LRU) and include caching headers for clients and proxies.',
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
        },
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/CveMetadata' },
            examples: {
              example: {
                summary: 'Typical CVE metadata payload',
                value: {
                  cveId: 'CVE-2024-12345',
                  publishedDate: '2024-06-12T09:30:00Z',
                  description: 'Cross-site scripting in ExampleCMS allows attackers to exfiltrate session cookies.',
                  cvssBase: 7.5,
                  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                  cpe: [
                    'cpe:2.3:a:examplecms:examplecms:3.2.1:*:*:*:*:*:*:*',
                  ],
                  modelVersion: '1',
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
