import { defineTask } from 'nitropack/runtime';
import { refreshKevFromRemote } from '~~/server/plugins/kev-loader';

export default defineTask({
  meta: {
    name: 'kev:refresh',
    description: 'Refresh the CISA Known Exploited Vulnerabilities cache',
  },
  async run() {
    return refreshKevFromRemote();
  },
});
