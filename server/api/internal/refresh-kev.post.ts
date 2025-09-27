import { createError, defineEventHandler, getHeader } from 'h3';
import { runTask } from 'nitropack/runtime';

export default defineEventHandler(async (event) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || getHeader(event, 'x-cron-secret') !== secret) {
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized' });
  }

  const result = await runTask('kev:refresh');
  return { ok: true, ...result };
});
