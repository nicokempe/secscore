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

const kevCacheFilePath: string = resolve(process.cwd(), KEV_COMPACT_PATH);
const kevFallbackFilePath: string = resolve(process.cwd(), KEV_FALLBACK_PATH);
let kevBootstrapPromise: Promise<void> | null = null;
let hasTriggeredInitialRefresh: boolean = false;

async function bootstrapKevRuntime(): Promise<void> {
  await ensureKevCacheDirectory();
  await hydrateKevFromLocalSources();
}

function scheduleInitialRefresh(): void {
  if (hasTriggeredInitialRefresh) {
    return;
  }
  hasTriggeredInitialRefresh = true;
  void refreshKevFromRemote();
}

async function ensureKevCacheDirectory(): Promise<void> {
  try {
    await mkdir(dirname(kevCacheFilePath), { recursive: true });
  }
  catch (error) {
    const logger = useLogger();
    const errorMessage: string = error instanceof Error ? error.message : String(error);
    logger.warn('kev.cache_dir_failed', {
      error: errorMessage,
    });
  }
}

async function hydrateKevFromLocalSources(): Promise<void> {
  const logger = useLogger();
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

function buildKevRequestHeaders(): Headers {
  const headers = new Headers({
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

function applyResponseHeadersToCompactFile(base: KevCompactFile, response: Response): KevCompactFile {
  const etag = response.headers.get('etag') ?? undefined;
  const lastModified = response.headers.get('last-modified') ?? undefined;
  return {
    ...base,
    etag,
    lastModified,
  };
}

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

export function isInKev(cveId: string): boolean {
  return getKevSet().has(cveId);
}

export function getKevMeta(cveId: string): KevMetaValue | undefined {
  return getKevMetaMap().get(cveId);
}

export function getKevStatus(): KevStatus {
  const metadata: KevRuntimeMetadata = getRuntimeMetadata();
  return {
    count: getKevSet().size,
    updatedAt: metadata.updatedAt,
    etag: metadata.etag,
    lastModified: metadata.lastModified,
  };
}

export async function ensureKevInitialized(): Promise<void> {
  if (!kevBootstrapPromise) {
    kevBootstrapPromise = bootstrapKevRuntime().catch((error): void => {
      kevBootstrapPromise = null;
      throw error;
    });
  }
  await kevBootstrapPromise;
}

export async function refreshKevFromRemote(): Promise<KevRefreshResult> {
  const logger = useLogger();
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
    const runtimeMetadata = getRuntimeMetadata();
    const updatedAt = runtimeMetadata.updatedAt ?? new Date().toISOString();
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
      const logger = useLogger();
      const errorMessage: string = error instanceof Error ? error.message : String(error);
      logger.warn('kev.bootstrap_failed', {
        error: errorMessage,
      });
    }
  });
});
