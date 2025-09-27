import { createError, defineEventHandler, getHeader } from 'h3';
import { refreshKevFromRemote } from '~~/server/plugins/kev-loader';

export default defineEventHandler(async (event) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || getHeader(event, 'x-cron-secret') !== secret) {
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized' });
  }

  const result = await refreshKevFromRemote();
  return { ok: true, ...result };
});
