import { defineNitroPlugin, runTask } from 'nitropack/runtime';
import type { NitroApp } from 'nitropack/types';
import { KEV_REFRESH_INTERVAL_HOURS } from '~~/server/lib/constants';

/**
 * Resolves the scheduler interval in hours, honoring environment overrides when valid.
 */
function parseIntervalHours(): number {
  const override = process.env.KEV_REFRESH_INTERVAL_HOURS;
  if (!override) {
    return KEV_REFRESH_INTERVAL_HOURS;
  }
  const parsed: number = Number.parseFloat(override);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return KEV_REFRESH_INTERVAL_HOURS;
  }
  return parsed;
}

export default defineNitroPlugin((nitroApp: NitroApp) => {
  if (process.env.DISABLE_KEV_SCHEDULER === '1') {
    return;
  }
  const hours: number = parseIntervalHours();
  if (!Number.isFinite(hours) || hours <= 0) {
    return;
  }
  const intervalMs: number = hours * 60 * 60 * 1000;

  let timer: ReturnType<typeof setInterval> | null = null;

  nitroApp.hooks.hook('request', (): void => {
    if (timer) {
      return;
    }
    timer = setInterval((): void => {
      void runTask('kev:refresh');
    }, intervalMs);
    if (
      typeof timer === 'object'
      && timer !== null
      && 'unref' in timer
      && typeof (timer as { unref?: () => void }).unref === 'function'
    ) {
      (timer as { unref?: () => void }).unref?.();
    }
  });

  nitroApp.hooks.hook('close', (): void => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  });
});
