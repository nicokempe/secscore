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
  type KevMetaValue,
  type KevCompactFile,
  type KevRuntimeMetadata,
} from '~~/server/lib/kev-index';

interface KevStatus {
  count: number
  updatedAt?: string
  etag?: string
  lastModified?: string
}

interface KevRefreshResult {
  changed: boolean
  count: number
  updatedAt: string
}

const cacheFilePath: string = resolve(process.cwd(), KEV_COMPACT_PATH);
const fallbackFilePath: string = resolve(process.cwd(), KEV_FALLBACK_PATH);
let bootstrapPromise: Promise<void> | null = null;
let initialRefreshTriggered: boolean = false;

async function bootstrapKevRuntime(): Promise<void> {
  await ensureCacheDirectory();
  await hydrateFromLocalSources();
}

function scheduleInitialRefresh(): void {
  if (initialRefreshTriggered) {
    return;
  }
  initialRefreshTriggered = true;
  void refreshKevFromRemote();
}

function log(level: 'info' | 'warn', msg: string, context?: Record<string, unknown>): void {
  const payload = {
    time: new Date().toISOString(),
    level,
    msg,
    ...(context ?? {}),
  };
  console.log(JSON.stringify(payload));
}

async function ensureCacheDirectory(): Promise<void> {
  try {
    await mkdir(dirname(cacheFilePath), { recursive: true });
  }
  catch (error) {
    log('warn', 'kev.cache_dir_failed', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function hydrateFromLocalSources(): Promise<void> {
  let source: 'cache' | 'fallback' | 'empty' = 'empty';
  let compact = loadCompactFromDisk(cacheFilePath);
  if (compact) {
    source = 'cache';
  }
  if (!compact) {
    const fallback = loadCompactFromDisk(fallbackFilePath);
    if (fallback) {
      compact = fallback;
      source = 'fallback';
      try {
        await saveCompactToDisk(cacheFilePath, compact);
      }
      catch (error) {
        log('warn', 'kev.cache_write_failed', {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  if (compact) {
    hydrateRuntime(compact);
    log('info', 'kev.bootstrap', {
      source,
      count: compact.items.length,
      updatedAt: compact.updatedAt,
    });
    return;
  }

  const empty: KevCompactFile = {
    updatedAt: new Date().toISOString(),
    items: [],
  };
  hydrateRuntime(empty);
  log('warn', 'kev.bootstrap_missing', { source });
}

function buildRequestHeaders(): Headers {
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

function responseHeadersToCompact(base: KevCompactFile, response: Response): KevCompactFile {
  const etag = response.headers.get('etag') ?? undefined;
  const lastModified = response.headers.get('last-modified') ?? undefined;
  return {
    ...base,
    etag,
    lastModified,
  };
}

async function fetchWithTimeout(input: string, headers: Headers): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout((): void => {
    controller.abort();
  }, KEV_FETCH_TIMEOUT_MS);
  try {
    const response: Response = await fetch(input, {
      headers,
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
  if (!bootstrapPromise) {
    bootstrapPromise = bootstrapKevRuntime().catch((error): void => {
      bootstrapPromise = null;
      throw error;
    });
  }
  await bootstrapPromise;
}

export async function refreshKevFromRemote(): Promise<KevRefreshResult> {
  try {
    const headers: Headers = buildRequestHeaders();
    const response: Response = await fetchWithTimeout(KEV_FEED_URL, headers);
    if (response.status === 304) {
      const metadata: KevRuntimeMetadata = getRuntimeMetadata();
      log('info', 'kev.refresh', {
        changed: false,
        status: response.status,
        count: getKevSet().size,
      });
      const updatedAt: string = metadata.updatedAt ?? new Date().toISOString();
      return { changed: false, count: getKevSet().size, updatedAt };
    }
    if (!response.ok) {
      throw new Error(`Unexpected response: ${response.status}`);
    }
    const payload = (await response.json()) as unknown;
    const compact: KevCompactFile = responseHeadersToCompact(buildCompactFromFull(payload), response);
    const next: KevCompactFile = {
      ...compact,
      updatedAt: new Date().toISOString(),
    };
    await saveCompactToDisk(cacheFilePath, next);
    hydrateRuntime(next);
    log('info', 'kev.refresh', {
      changed: true,
      status: response.status,
      count: next.items.length,
      updatedAt: next.updatedAt,
    });
    return { changed: true, count: next.items.length, updatedAt: next.updatedAt };
  }
  catch (error) {
    log('warn', 'kev.refresh_failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    const metadata = getRuntimeMetadata();
    const updatedAt = metadata.updatedAt ?? new Date().toISOString();
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
      log('warn', 'kev.bootstrap_failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });
});
