import { ENRICH_CACHE_MAX_ENTRIES } from '~~/server/lib/constants';
import type { CacheEntry } from '~/types/cache.types';

const cacheStore = new Map<string, CacheEntry<unknown>>();

/**
 * Retrieves a cached value by key, returning `null` when the entry is absent or expired.
 */
export function lruGet<T>(key: string): T | null {
  const existing = cacheStore.get(key);
  if (!existing) {
    return null;
  }

  if (existing.expiresAt <= Date.now()) {
    cacheStore.delete(key);
    return null;
  }

  cacheStore.delete(key);
  cacheStore.set(key, existing);
  return existing.value as T;
}

/**
 * Stores a value in the cache with the provided TTL (in milliseconds), evicting the oldest entry when capacity is exceeded.
 */
export function lruSet<T>(key: string, value: T, ttlMs: number): void {
  const expiresAt: number = Date.now() + ttlMs;
  cacheStore.set(key, { value, expiresAt });

  if (cacheStore.size > ENRICH_CACHE_MAX_ENTRIES) {
    const oldestKey = cacheStore.keys().next().value;
    if (oldestKey) {
      cacheStore.delete(oldestKey);
    }
  }
}
