import { E_MAX_V31, E_MIN_V31, EPSS_BLEND_WEIGHT, EXPLOITPROB_WEIGHT, KEV_MIN_FLOOR, POC_BONUS_MAX } from '~~/server/lib/constants';
import type { EpssSignal, ExploitEvidence } from '~~/server/types/secscore';

const BASE_DEFAULT = 0;

/** Parameters required to compose an explanation object. */
interface ExplanationParams {
  kev: boolean
  exploits: ExploitEvidence[]
  epss: EpssSignal | null
  exploitProb: number
  modelCategory: string
  modelParams: { mu: number, lambda: number, kappa: number }
  tWeeks: number
  cvssBase: number | null
  secscore: number
}

/**
 * Infers a model category from CPE strings to select the appropriate AL parameter set.
 */
export function inferCategory(cpeList: string[]): string {
  for (const cpe of cpeList) {
    const lowered = cpe.toLowerCase();
    if (lowered.includes('php') || lowered.includes('wordpress')) {
      return 'php';
    }
    if (lowered.includes('linux') || lowered.includes('kernel')) {
      return 'linux';
    }
    if (lowered.includes('microsoft') || lowered.includes('windows')) {
      return 'windows';
    }
  }
  return 'default';
}

/**
 * Computes the asymmetric Laplace cumulative distribution function for the provided parameters.
 */
export function asymmetricLaplaceCdf(tWeeks: number, mu: number, lambda: number, kappa: number): number {
  if (!Number.isFinite(tWeeks) || !Number.isFinite(mu) || !Number.isFinite(lambda) || !Number.isFinite(kappa)) {
    return 0;
  }

  if (tWeeks <= mu) {
    const value = (kappa ** 2 / (1 + kappa ** 2)) * Math.exp((lambda / kappa) * (tWeeks - mu));
    return clamp(value, 0, 1);
  }

  const value = 1 - (1 / (1 + kappa ** 2)) * Math.exp(-lambda * kappa * (tWeeks - mu));
  return clamp(value, 0, 1);
}

/**
 * Combines CVSS base, exploit probability, KEV status, exploit evidence, and EPSS to compute the SecScore.
 */
export function computeSecScore(args: {
  cvssBase: number | null
  exploitProb: number
  kev: boolean
  hasExploit: boolean
  epss: EpssSignal | null
}): number {
  const baseScore = typeof args.cvssBase === 'number' ? args.cvssBase : BASE_DEFAULT;
  const temporalFactor = E_MIN_V31 + (E_MAX_V31 - E_MIN_V31) * args.exploitProb;
  const blendedTemporal = baseScore * ((1 - EXPLOITPROB_WEIGHT) + temporalFactor * EXPLOITPROB_WEIGHT);
  const pocBonus = args.hasExploit ? POC_BONUS_MAX : 0;
  const epssBonus = args.epss ? args.epss.score * EPSS_BLEND_WEIGHT : 0;
  let score = blendedTemporal + pocBonus + epssBonus;

  if (args.kev && score < KEV_MIN_FLOOR) {
    score = KEV_MIN_FLOOR;
  }

  return Math.round(clamp(score, 0, 10) * 10) / 10;
}

/**
 * Builds human-readable explanation bullets summarizing why a CVE received a particular SecScore.
 */
export function buildExplanation(params: ExplanationParams): Array<{ title: string, detail: string, source: string }> {
  const explanation: Array<{ title: string, detail: string, source: string }> = [];

  if (params.kev) {
    explanation.push({ title: 'CISA KEV', detail: 'Listed by CISA KEV', source: 'cisa-kev' });
  }

  const exploit = params.exploits[0];
  if (exploit) {
    const dateText = exploit.publishedDate ? ` from ${exploit.publishedDate.split('T')[0]}` : '';
    explanation.push({ title: 'Exploit PoC', detail: `ExploitDB entry${dateText}`, source: 'exploitdb' });
  }

  if (params.epss) {
    const percentile = Math.round(params.epss.percentile * 100);
    explanation.push({ title: 'EPSS', detail: `EPSS=${params.epss.score.toFixed(2)} (p${percentile})`, source: 'epss' });
  }

  explanation.push({
    title: 'Time-aware',
    detail: `AL-CDF exploitProb=${params.exploitProb.toFixed(2)} at tWeeks=${params.tWeeks.toFixed(1)} for category=${params.modelCategory} (mu=${params.modelParams.mu.toFixed(2)}, lambda=${params.modelParams.lambda.toFixed(2)}, kappa=${params.modelParams.kappa.toFixed(2)})`,
    source: 'secscore',
  });

  if (typeof params.cvssBase === 'number') {
    explanation.push({
      title: 'CVSS Base',
      detail: `CVSS base score ${params.cvssBase.toFixed(1)}`,
      source: 'cvss',
    });
  }

  explanation.push({
    title: 'SecScore',
    detail: `Final SecScore ${params.secscore.toFixed(1)}`,
    source: 'secscore',
  });

  return explanation;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}
