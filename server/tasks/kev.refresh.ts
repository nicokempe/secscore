import { refreshKevFromRemote } from '~~/server/plugins/kev-loader';

export default async (): Promise<void> => {
  await refreshKevFromRemote();
};
