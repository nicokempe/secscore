import { createError, getRequestIP, H3Event } from 'h3';
import { DEFAULT_RATE_LIMIT_PER_HOUR } from '~~/server/lib/constants';

const ONE_HOUR_MS = 60 * 60 * 1000;
const requestBuckets = new Map<string, number[]>();

/**
 * Applies a sliding window rate limit per client IP address.
 * The window spans one hour and tracks request timestamps, removing stale entries on each invocation.
 * When the number of requests exceeds the configured threshold, an HTTP 429 error is thrown.
 */
export async function applyPerIpRateLimit(
  event: H3Event,
  opts: { limitPerHour: number } = { limitPerHour: DEFAULT_RATE_LIMIT_PER_HOUR },
): Promise<void> {
  const ip = getRequestIP(event, { xForwardedFor: true }) ?? 'unknown';
  const limit = opts.limitPerHour;
  const now = Date.now();
  const windowStart = now - ONE_HOUR_MS;

  const timestamps = requestBuckets.get(ip) ?? [];
  const recentTimestamps = timestamps.filter(timestamp => timestamp >= windowStart);

  if (recentTimestamps.length >= limit) {
    throw createError({ statusCode: 429, statusMessage: 'Rate limit exceeded' });
  }

  recentTimestamps.push(now);
  requestBuckets.set(ip, recentTimestamps);
}
