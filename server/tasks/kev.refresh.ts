import { defineTask } from 'nitropack/runtime';
import { ensureKevInitialized, refreshKevFromRemote } from '~~/server/plugins/kev-loader';

export default defineTask({
  meta: {
    name: 'kev:refresh',
    description: 'Refresh the CISA Known Exploited Vulnerabilities cache',
  },
  async run(taskContext) {
    void taskContext;
    await ensureKevInitialized();
    const result = await refreshKevFromRemote();
    return { result };
  },
});
