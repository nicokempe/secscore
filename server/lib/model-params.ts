import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AL_PARAMS_FILE } from '~~/server/lib/constants';
import type { ModelParameters } from '~/types/model-params.types';

const FALLBACK_PARAMS: ModelParameters = {
  default: { mu: -0.2857, lambda: 21.79, kappa: 0.9075 },
  php: { mu: -0.4286, lambda: 14.56, kappa: 1.128 },
  linux: { mu: 0.8571, lambda: 25.59, kappa: 0.8485 },
  windows: { mu: -0.1429, lambda: 32.31, kappa: 0.7502 },
  webapps: { mu: -0.2857, lambda: 21.79, kappa: 0.9075 },
  remote: { mu: -0.2857, lambda: 21.79, kappa: 0.9075 },
  local: { mu: -0.2857, lambda: 21.79, kappa: 0.9075 },
  dos: { mu: 0.8571, lambda: 25.59, kappa: 0.8485 },
  java: { mu: -0.4286, lambda: 14.56, kappa: 1.128 },
  asp: { mu: -0.1429, lambda: 32.31, kappa: 0.7502 },
  android: { mu: -0.2857, lambda: 21.79, kappa: 0.9075 },
  ios: { mu: -0.1429, lambda: 32.31, kappa: 0.7502 },
  macos: { mu: -0.1429, lambda: 32.31, kappa: 0.7502 },
  hardware: { mu: 0.8571, lambda: 25.59, kappa: 0.8485 },
};

let paramsCache: ModelParameters | null = null;

/**
 * Reads the asymmetric Laplace model parameters for the requested category, falling back to the default set.
 */
export async function readModelParams(category: string): Promise<{ mu: number, lambda: number, kappa: number }> {
  if (!paramsCache) {
    try {
      const filePath: string = resolve(process.cwd(), AL_PARAMS_FILE);
      const contents: string = await readFile(filePath, 'utf8');
      paramsCache = JSON.parse(contents) as ModelParameters;
    }
    catch {
      paramsCache = FALLBACK_PARAMS;
    }
  }

  const selected = paramsCache?.[category] ?? paramsCache?.default;
  if (!selected) {
    throw new Error('Model parameters unavailable');
  }

  return selected;
}
