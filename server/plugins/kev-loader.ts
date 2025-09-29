import { useLogger } from '~/composables/useLogger';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { defineNitroPlugin } from 'nitropack/runtime';
import {
  KEV_COMPACT_PATH,
  KEV_FALLBACK_PATH,
  KEV_FEED_URL,
  KEV_FETCH_TIMEOUT_MS,
  USER_AGENT,
} from '~~/server/lib/constants';
import {
  buildCompactFromFull,
  getKevMetaMap,
  getKevSet,
  getRuntimeMetadata,
  hydrateRuntime,
  loadCompactFromDisk,
  saveCompactToDisk,
} from '~~/server/lib/kev-index';
import type { KevCompactFile, KevMetaValue, KevRefreshResult, KevRuntimeMetadata, KevStatus } from '~/types/kev.types';
import type { Logger } from '~/types/logger.types';

const kevCacheFilePath: string = resolve(process.cwd(), KEV_COMPACT_PATH);
const kevFallbackFilePath: string = resolve(process.cwd(), KEV_FALLBACK_PATH);
let kevBootstrapPromise: Promise<void> | null = null;
let hasTriggeredInitialRefresh: boolean = false;

/**
 * Bootstraps the in-memory KEV runtime from cache/fallback sources.
 */
async function bootstrapKevRuntime(): Promise<void> {
  await ensureKevCacheDirectory();
  await hydrateKevFromLocalSources();
}

/**
 * Defers the first KEV refresh until the initial request to avoid wasted work in cold starts.
 */
function scheduleInitialRefresh(): void {
  if (hasTriggeredInitialRefresh) {
    return;
  }
  hasTriggeredInitialRefresh = true;
  void refreshKevFromRemote();
}

/**
 * Creates the on-disk directory used to persist the compact KEV cache file.
 */
async function ensureKevCacheDirectory(): Promise<void> {
  try {
    await mkdir(dirname(kevCacheFilePath), { recursive: true });
  }
  catch (error) {
    const logger: Logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('kev.cache_dir_failed', {
      error: errorMessage,
    });
  }
}

/**
 * Attempts to hydrate the runtime cache from disk (cache or fallback), or initializes an empty dataset.
 */
async function hydrateKevFromLocalSources(): Promise<void> {
  const logger: Logger = useLogger();
  let hydrationSource: 'cache' | 'fallback' | 'empty' = 'empty';
  let cachedCompactFile = loadCompactFromDisk(kevCacheFilePath);
  if (cachedCompactFile) {
    hydrationSource = 'cache';
  }
  if (!cachedCompactFile) {
    const fallbackCompactFile = loadCompactFromDisk(kevFallbackFilePath);
    if (fallbackCompactFile) {
      cachedCompactFile = fallbackCompactFile;
      hydrationSource = 'fallback';
      try {
        await saveCompactToDisk(kevCacheFilePath, cachedCompactFile);
      }
      catch (error) {
        const errorMessage: string = error instanceof Error ? error.message : String(error);
        logger.warn('kev.cache_write_failed', {
          error: errorMessage,
        });
      }
    }
  }

  if (cachedCompactFile) {
    hydrateRuntime(cachedCompactFile);
    logger.info('kev.bootstrap', {
      source: hydrationSource,
      count: cachedCompactFile.items.length,
      updatedAt: cachedCompactFile.updatedAt,
    });
    return;
  }

  const emptyCompactFile: KevCompactFile = {
    updatedAt: new Date().toISOString(),
    items: [],
  };
  hydrateRuntime(emptyCompactFile);
  logger.warn('kev.bootstrap_missing', { source: hydrationSource });
}

/**
 * Builds request headers for the KEV feed, including conditional request metadata.
 */
function buildKevRequestHeaders(): Headers {
  const headers: Headers = new Headers({
    'User-Agent': USER_AGENT,
    'Accept': 'application/json',
  });
  const metadata: KevRuntimeMetadata = getRuntimeMetadata();
  if (metadata.etag) {
    headers.set('If-None-Match', metadata.etag);
  }
  if (metadata.lastModified) {
    headers.set('If-Modified-Since', metadata.lastModified);
  }
  return headers;
}

/**
 * Merges caching headers from an upstream response into the compact KEV file structure.
 */
function applyResponseHeadersToCompactFile(base: KevCompactFile, response: Response): KevCompactFile {
  const etag = response.headers.get('etag') ?? undefined;
  const lastModified = response.headers.get('last-modified') ?? undefined;
  return {
    ...base,
    etag,
    lastModified,
  };
}

/**
 * Performs a fetch with an explicit timeout using `AbortController` for hard cancellations.
 */
async function fetchKevWithTimeout(requestUrl: string, requestHeaders: Headers): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout((): void => {
    controller.abort();
  }, KEV_FETCH_TIMEOUT_MS);
  try {
    const response: Response = await fetch(requestUrl, {
      headers: requestHeaders,
      signal: controller.signal,
    });
    return response;
  }
  finally {
    clearTimeout(timeout);
  }
}

/**
 * Determines whether a CVE identifier is currently listed in CISA KEV.
 */
export function isInKev(cveId: string): boolean {
  return getKevSet().has(cveId);
}

/**
 * Retrieves cached metadata for a specific KEV entry, if available.
 */
export function getKevMeta(cveId: string): KevMetaValue | undefined {
  return getKevMetaMap().get(cveId);
}

/**
 * Provides dataset-wide KEV status information for response headers or diagnostics.
 */
export function getKevStatus(): KevStatus {
  const metadata: KevRuntimeMetadata = getRuntimeMetadata();
  return {
    count: getKevSet().size,
    updatedAt: metadata.updatedAt,
    etag: metadata.etag,
    lastModified: metadata.lastModified,
  };
}

/**
 * Ensures KEV data has been hydrated before responding to a request.
 */
export async function ensureKevInitialized(): Promise<void> {
  if (!kevBootstrapPromise) {
    kevBootstrapPromise = bootstrapKevRuntime().catch((error): void => {
      kevBootstrapPromise = null;
      throw error;
    });
  }
  await kevBootstrapPromise;
}

/**
 * Fetches the latest KEV dataset, updating caches and persisting to disk.
 */
export async function refreshKevFromRemote(): Promise<KevRefreshResult> {
  const logger: Logger = useLogger();
  try {
    const requestHeaders: Headers = buildKevRequestHeaders();
    const kevResponse: Response = await fetchKevWithTimeout(KEV_FEED_URL, requestHeaders);
    if (kevResponse.status === 304) {
      const runtimeMetadata: KevRuntimeMetadata = getRuntimeMetadata();
      logger.info('kev.refresh', {
        changed: false,
        status: kevResponse.status,
        count: getKevSet().size,
      });
      const updatedAt: string = runtimeMetadata.updatedAt ?? new Date().toISOString();
      return { changed: false, count: getKevSet().size, updatedAt };
    }
    if (!kevResponse.ok) {
      throw new Error(`Unexpected response: ${kevResponse.status}`);
    }
    const kevPayload = (await kevResponse.json()) as unknown;
    const baseCompactFile: KevCompactFile = applyResponseHeadersToCompactFile(buildCompactFromFull(kevPayload), kevResponse);
    const updatedCompactFile: KevCompactFile = {
      ...baseCompactFile,
      updatedAt: new Date().toISOString(),
    };
    await saveCompactToDisk(kevCacheFilePath, updatedCompactFile);
    hydrateRuntime(updatedCompactFile);
    logger.info('kev.refresh', {
      changed: true,
      status: kevResponse.status,
      count: updatedCompactFile.items.length,
      updatedAt: updatedCompactFile.updatedAt,
    });
    return { changed: true, count: updatedCompactFile.items.length, updatedAt: updatedCompactFile.updatedAt };
  }
  catch (error) {
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('kev.refresh_failed', {
      error: errorMessage,
    });
    const runtimeMetadata: KevRuntimeMetadata = getRuntimeMetadata();
    const updatedAt: string = runtimeMetadata.updatedAt ?? new Date().toISOString();
    return { changed: false, count: getKevSet().size, updatedAt };
  }
}

export default defineNitroPlugin((nitroApp): void => {
  nitroApp.hooks.hook('request', async (): Promise<void> => {
    try {
      await ensureKevInitialized();
      scheduleInitialRefresh();
    }
    catch (error) {
      const logger: Logger = useLogger();
      const errorMessage: string = error instanceof Error ? error.message : String(error);
      logger.warn('kev.bootstrap_failed', {
        error: errorMessage,
      });
    }
  });
});
