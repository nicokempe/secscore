import { E_MAX, E_MIN_V31, EPSS_BLEND_WEIGHT, KEV_MIN_FLOOR, POC_BONUS_MAX } from '~~/server/lib/constants';
import type { CvssTemporalMultipliers, EpssSignal } from '~/types/secscore.types';
import type { ExplanationParams } from '~/types/secscore-engine.types';

const BASE_DEFAULT = 0;
const EXPONENT_BOUND = 50;
const CVSS_V4_EXPLOIT_MATURITY: Record<string, number> = {
  A: 1.0,
  X: 1.0,
  P: 0.95,
  U: 0.9,
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function clamp01(value: number): number {
  return clamp(value, 0, 1);
}

function safeExp(exponent: number): number {
  if (exponent <= -EXPONENT_BOUND) {
    return 0;
  }
  if (exponent >= EXPONENT_BOUND) {
    return Math.exp(EXPONENT_BOUND);
  }
  return Math.exp(exponent);
}

function roundToTenth(value: number): number {
  return Math.round((value + Number.EPSILON) * 10) / 10;
}

function tryComputeEminFromCvssV4(vector: string | null): number | null {
  if (!vector || !vector.startsWith('CVSS:4.0/')) {
    return null;
  }
  const eHigh = CVSS_V4_EXPLOIT_MATURITY.A ?? null;
  const eUnproven = CVSS_V4_EXPLOIT_MATURITY.U ?? null;
  if (eHigh === null || eUnproven === null || eHigh <= 0) {
    return null;
  }
  return clamp01(eUnproven / eHigh);
}

function resolveTemporalMultiplier(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 1;
}

function normalizeExploitProb(probability: number): number {
  if (!Number.isFinite(probability)) {
    return 0;
  }
  return clamp01(probability);
}

/**
 * Infers a model category from CPE strings to select the appropriate AL parameter set.
 */
export function inferCategory(cpeList: string[]): string {
  if (!Array.isArray(cpeList) || cpeList.length === 0) {
    return 'default';
  }

  const lowered = cpeList.map(cpe => cpe.toLowerCase());
  const includes = (needle: string): boolean => lowered.some(entry => entry.includes(needle));

  // 1. PHP-centric stacks and CMS ecosystems.
  if (includes('php')) {
    return 'php';
  }
  if (lowered.some(entry => entry.includes('wordpress') || entry.includes('joomla'))) {
    return 'webapps';
  }

  // 2. Microsoft Windows platforms.
  if (lowered.some(entry => entry.includes('microsoft') || entry.includes('windows'))) {
    return 'windows';
  }

  // 3. Linux kernels and distributions.
  if (lowered.some(entry => entry.includes('linux') || entry.includes('kernel'))) {
    return 'linux';
  }

  // 4. Mobile and desktop operating systems.
  if (lowered.some(entry => entry.includes('android') || entry.includes('google:android'))) {
    return 'android';
  }
  if (lowered.some(entry => entry.includes('apple:iphone_os') || entry.includes('ios'))) {
    return 'ios';
  }
  if (lowered.some(entry => entry.includes('apple:mac_os_x') || entry.includes('macos'))) {
    return 'macos';
  }

  // 5. Language/runtime specific ecosystems.
  if (lowered.some(entry => entry.includes('oracle:java') || entry.includes(':java') || entry.includes('openjdk') || entry.includes('jdk'))) {
    return 'java';
  }

  // 6. Explicit DoS indicators.
  if (lowered.some(entry => entry.includes('denial_of_service') || entry.includes(':dos') || entry.includes('/dos'))) {
    return 'dos';
  }

  // 7. ASP.NET applications.
  if (lowered.some(entry => entry.includes('asp.net') || entry.includes('aspnet'))) {
    return 'asp';
  }

  // 8. Hardware and firmware indicators.
  if (lowered.some(entry => entry.includes(':h:') || entry.includes('firmware') || entry.includes('hardware'))) {
    return 'hardware';
  }

  // 9. Explicit remote/local hints fall back to coarse categories.
  if (lowered.some(entry => entry.includes('remote'))) {
    return 'remote';
  }
  if (lowered.some(entry => entry.includes('local'))) {
    return 'local';
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

  const clampedWeeks = Math.max(0, tWeeks);

  if (clampedWeeks <= mu) {
    const exponent = (lambda / kappa) * (clampedWeeks - mu);
    const value = (kappa ** 2 / (1 + kappa ** 2)) * safeExp(exponent);
    return clamp01(value);
  }

  const exponent = -lambda * kappa * (clampedWeeks - mu);
  const value = 1 - (1 / (1 + kappa ** 2)) * safeExp(exponent);
  return clamp01(value);
}

export interface ComputeSecScoreArgs {
  cvssBase: number | null
  cvssVector: string | null
  cvssVersion: string | null
  exploitProb: number
  kev: boolean
  hasExploit: boolean
  epss: EpssSignal | null
  temporalMultipliers?: CvssTemporalMultipliers
}

export interface ComputeSecScoreResult {
  secscore: number
  temporalKernel: number
  exploitMaturity: number
  eMin: number
}

/**
 * Combines CVSS base score, temporal multipliers, exploit probability, KEV status, exploit evidence, and EPSS to compute the SecScore.
 */
export function computeSecScore(args: ComputeSecScoreArgs): ComputeSecScoreResult {
  const baseScore = typeof args.cvssBase === 'number' && Number.isFinite(args.cvssBase) ? args.cvssBase : BASE_DEFAULT;
  const remediationMultiplier = resolveTemporalMultiplier(args.temporalMultipliers?.remediationLevel ?? null);
  const reportConfidenceMultiplier = resolveTemporalMultiplier(args.temporalMultipliers?.reportConfidence ?? null);
  const temporalKernel = roundToTenth(baseScore * remediationMultiplier * reportConfidenceMultiplier);

  const exploitProb = normalizeExploitProb(args.exploitProb);
  const eMin = args.cvssVersion?.startsWith('4')
    ? tryComputeEminFromCvssV4(args.cvssVector)
    : null;
  const effectiveEmin = typeof eMin === 'number' ? clamp01(eMin) : E_MIN_V31;
  const exploitMaturity = effectiveEmin + (E_MAX - effectiveEmin) * exploitProb;

  let coreScore = temporalKernel * exploitMaturity;
  if (args.epss) {
    coreScore += EPSS_BLEND_WEIGHT * args.epss.score;
  }
  if (args.hasExploit) {
    coreScore += POC_BONUS_MAX;
  }
  if (args.kev && coreScore < KEV_MIN_FLOOR) {
    coreScore = KEV_MIN_FLOOR;
  }

  const finalScore = roundToTenth(clamp(coreScore, 0, 10));
  return {
    secscore: finalScore,
    temporalKernel,
    exploitMaturity,
    eMin: effectiveEmin,
  };
}

/**
 * Builds human-readable explanation bullets summarizing why a CVE received a particular SecScore.
 */
export function buildExplanation(params: ExplanationParams & { temporalKernel: number, temporalExploitMaturity: number }): Array<{ title: string, detail: string, source: string }> {
  const explanation: Array<{ title: string, detail: string, source: string }> = [];

  explanation.push({
    title: 'Temporal model',
    detail:
      `category=${params.modelCategory}, mu=${params.modelParams.mu.toFixed(2)}, lambda=${params.modelParams.lambda.toFixed(2)}, `
      + `kappa=${params.modelParams.kappa.toFixed(2)}, tWeeks=${params.tWeeks.toFixed(2)}, `
      + `exploitProb=${params.exploitProb.toFixed(3)}, E_S(t)=${params.temporalExploitMaturity.toFixed(3)}, `
      + `K=${params.temporalKernel.toFixed(1)}`,
    source: 'secscore',
  });

  if (params.kev) {
    explanation.push({
      title: 'CISA KEV',
      detail: `Applied KEV floor to ≥ ${KEV_MIN_FLOOR.toFixed(1)} after temporal kernel`,
      source: 'cisa-kev',
    });
  }

  const exploit = params.exploits[0];
  if (exploit) {
    const dateText = exploit.publishedDate ? ` (published ${exploit.publishedDate.split('T')[0]})` : '';
    explanation.push({
      title: 'Exploit PoC',
      detail: `Added +${POC_BONUS_MAX.toFixed(1)} after temporal kernel from ExploitDB${dateText}`,
      source: 'exploitdb',
    });
  }

  if (params.epss) {
    const percentile = Math.round(params.epss.percentile * 100);
    const bonus = EPSS_BLEND_WEIGHT * params.epss.score;
    explanation.push({
      title: 'EPSS',
      detail: `Added +${bonus.toFixed(2)} (EPSS=${params.epss.score.toFixed(3)}, p${percentile}) after temporal kernel`,
      source: 'epss',
    });
  }

  if (typeof params.cvssBase === 'number') {
    explanation.push({
      title: 'CVSS Base',
      detail: `CVSS base score ${params.cvssBase.toFixed(1)} used for kernel`,
      source: 'cvss',
    });
  }
  else {
    explanation.push({
      title: 'CVSS Missing',
      detail: 'CVSS base score unavailable; kernel defaults to 0',
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
