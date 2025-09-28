import { E_MAX, E_MIN_V31, EPSS_BLEND_WEIGHT, KEV_MIN_FLOOR, POC_BONUS_MAX } from '~~/server/lib/constants';
import type { CvssTemporalMultipliers, EpssSignal } from '~/types/secscore.types';
import type { ExplanationParams } from '~/types/secscore-engine.types';

const BASE_DEFAULT: number = 0;
const EXPONENT_BOUND: number = 50;
const CVSS_V4_EXPLOIT_MATURITY: Record<string, number> = {
  A: 1.0,
  X: 1.0,
  P: 0.95,
  U: 0.9,
};

/**
 * Restricts a numeric value to a closed interval.
 *
 * @param value - Candidate number to clamp.
 * @param min - Lower inclusive bound.
 * @param max - Upper inclusive bound.
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Convenience wrapper ensuring values remain within the probability domain `[0, 1]`.
 */
function clampBetweenZeroAndOne(value: number): number {
  return clamp(value, 0, 1);
}

/**
 * Computes `e^x` while preventing overflow/underflow by enforcing exponent bounds.
 *
 * @param exponent - Exponent to evaluate.
 * @returns Exponential result constrained to a safe numeric range.
 */
function computeBoundedExponential(exponent: number): number {
  if (exponent <= -EXPONENT_BOUND) {
    return 0;
  }
  if (exponent >= EXPONENT_BOUND) {
    return Math.exp(EXPONENT_BOUND);
  }
  return Math.exp(exponent);
}

/**
 * Rounds a floating point number to one decimal place using half-away-from-zero semantics.
 */
function roundToNearestTenth(value: number): number {
  return Math.round((value + Number.EPSILON) * 10) / 10;
}

/**
 * Derives a minimum exploitability floor from CVSS v4 vectors when available.
 *
 * @param vector - Optional CVSS vector string.
 * @returns Ratio of unproven to high exploit maturity or `null` when unavailable.
 */
function inferMinimumExploitabilityFromCvssV4(vector: string | null): number | null {
  if (!vector || !vector.startsWith('CVSS:4.0/')) {
    return null;
  }
  const maturityHigh = CVSS_V4_EXPLOIT_MATURITY.A ?? null;
  const maturityUnproven = CVSS_V4_EXPLOIT_MATURITY.U ?? null;
  if (maturityHigh === null || maturityUnproven === null || maturityHigh <= 0) {
    return null;
  }
  return clampBetweenZeroAndOne(maturityUnproven / maturityHigh);
}

/**
 * Returns numeric temporal multipliers while defaulting to neutral values.
 */
function resolveTemporalMultiplierOrDefault(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 1;
}

/**
 * Safely normalizes exploit probability estimates to the `[0, 1]` interval.
 */
function normalizeExploitProbability(probability: number): number {
  if (!Number.isFinite(probability)) {
    return 0;
  }
  return clampBetweenZeroAndOne(probability);
}

/**
 * Infers a model category from CPE strings to select the appropriate AL parameter set.
 */
export function inferCategory(cpeList: string[]): string {
  if (!Array.isArray(cpeList) || cpeList.length === 0) {
    return 'default';
  }

  const normalizedCpeEntries = cpeList.map(cpe => cpe.toLowerCase());
  const cpeIncludesNeedle = (needle: string): boolean => normalizedCpeEntries.some(entry => entry.includes(needle));

  // 1. PHP-centric stacks and CMS ecosystems.
  if (cpeIncludesNeedle('php')) {
    return 'php';
  }
  if (normalizedCpeEntries.some(entry => entry.includes('wordpress') || entry.includes('joomla'))) {
    return 'webapps';
  }

  // 2. Microsoft Windows platforms.
  if (normalizedCpeEntries.some(entry => entry.includes('microsoft') || entry.includes('windows'))) {
    return 'windows';
  }

  // 3. Linux kernels and distributions.
  if (normalizedCpeEntries.some(entry => entry.includes('linux') || entry.includes('kernel'))) {
    return 'linux';
  }

  // 4. Mobile and desktop operating systems.
  if (normalizedCpeEntries.some(entry => entry.includes('android') || entry.includes('google:android'))) {
    return 'android';
  }
  if (normalizedCpeEntries.some(entry => entry.includes('apple:iphone_os') || entry.includes('ios'))) {
    return 'ios';
  }
  if (normalizedCpeEntries.some(entry => entry.includes('apple:mac_os_x') || entry.includes('macos'))) {
    return 'macos';
  }

  // 5. Language/runtime specific ecosystems.
  if (normalizedCpeEntries.some(entry => entry.includes('oracle:java') || entry.includes(':java') || entry.includes('openjdk') || entry.includes('jdk'))) {
    return 'java';
  }

  // 6. Explicit DoS indicators.
  if (normalizedCpeEntries.some(entry => entry.includes('denial_of_service') || entry.includes(':dos') || entry.includes('/dos'))) {
    return 'dos';
  }

  // 7. ASP.NET applications.
  if (normalizedCpeEntries.some(entry => entry.includes('asp.net') || entry.includes('aspnet'))) {
    return 'asp';
  }

  // 8. Hardware and firmware indicators.
  if (normalizedCpeEntries.some(entry => entry.includes(':h:') || entry.includes('firmware') || entry.includes('hardware'))) {
    return 'hardware';
  }

  // 9. Explicit remote/local hints fall back to coarse categories.
  if (normalizedCpeEntries.some(entry => entry.includes('remote'))) {
    return 'remote';
  }
  if (normalizedCpeEntries.some(entry => entry.includes('local'))) {
    return 'local';
  }

  return 'default';
}

/**
 * Computes the asymmetric Laplace cumulative distribution function for the provided parameters.
 */
export function asymmetricLaplaceCdf(weeksSincePublication: number, mu: number, lambda: number, kappa: number): number {
  if (!Number.isFinite(weeksSincePublication) || !Number.isFinite(mu) || !Number.isFinite(lambda) || !Number.isFinite(kappa)) {
    return 0;
  }

  const nonNegativeWeeks: number = Math.max(0, weeksSincePublication);

  if (nonNegativeWeeks <= mu) {
    const exponent: number = (lambda / kappa) * (nonNegativeWeeks - mu);
    const cdfValue: number = (kappa ** 2 / (1 + kappa ** 2)) * computeBoundedExponential(exponent);
    return clampBetweenZeroAndOne(cdfValue);
  }

  const exponent: number = -lambda * kappa * (nonNegativeWeeks - mu);
  const cdfValue: number = 1 - (1 / (1 + kappa ** 2)) * computeBoundedExponential(exponent);
  return clampBetweenZeroAndOne(cdfValue);
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
export function computeSecScore(scoreInput: ComputeSecScoreArgs): ComputeSecScoreResult {
  const baseScore: number = typeof scoreInput.cvssBase === 'number' && Number.isFinite(scoreInput.cvssBase)
    ? scoreInput.cvssBase
    : BASE_DEFAULT;
  const remediationMultiplier: number = resolveTemporalMultiplierOrDefault(scoreInput.temporalMultipliers?.remediationLevel ?? null);
  const reportConfidenceMultiplier: number = resolveTemporalMultiplierOrDefault(scoreInput.temporalMultipliers?.reportConfidence ?? null);
  const temporalKernel: number = roundToNearestTenth(baseScore * remediationMultiplier * reportConfidenceMultiplier);

  const normalizedExploitProbability: number = normalizeExploitProbability(scoreInput.exploitProb);
  const minimumExploitability = scoreInput.cvssVersion?.startsWith('4')
    ? inferMinimumExploitabilityFromCvssV4(scoreInput.cvssVector)
    : null;
  const effectiveMinimumExploitability: number = typeof minimumExploitability === 'number'
    ? clampBetweenZeroAndOne(minimumExploitability)
    : E_MIN_V31;
  const exploitMaturity: number = effectiveMinimumExploitability + (E_MAX - effectiveMinimumExploitability) * normalizedExploitProbability;

  let intermediateScore: number = temporalKernel * exploitMaturity;
  if (scoreInput.epss) {
    intermediateScore += EPSS_BLEND_WEIGHT * scoreInput.epss.score;
  }
  if (scoreInput.hasExploit) {
    intermediateScore += POC_BONUS_MAX;
  }
  if (scoreInput.kev && intermediateScore < KEV_MIN_FLOOR) {
    intermediateScore = KEV_MIN_FLOOR;
  }

  const normalizedFinalScore = roundToNearestTenth(clamp(intermediateScore, 0, 10));
  return {
    secscore: normalizedFinalScore,
    temporalKernel,
    exploitMaturity,
    eMin: effectiveMinimumExploitability,
  };
}

/**
 * Builds human-readable explanation bullets summarizing why a CVE received a particular SecScore.
 */
export function buildExplanation(explanationParams: ExplanationParams & { temporalKernel: number, temporalExploitMaturity: number }): Array<{ title: string, detail: string, source: string }> {
  const explanationEntries: Array<{ title: string, detail: string, source: string }> = [];

  explanationEntries.push({
    title: 'Temporal model',
    detail:
      `category=${explanationParams.modelCategory}, mu=${explanationParams.modelParams.mu.toFixed(2)}, lambda=${explanationParams.modelParams.lambda.toFixed(2)}, `
      + `kappa=${explanationParams.modelParams.kappa.toFixed(2)}, tWeeks=${explanationParams.tWeeks.toFixed(2)}, `
      + `exploitProb=${explanationParams.exploitProb.toFixed(3)}, E_S(t)=${explanationParams.temporalExploitMaturity.toFixed(3)}, `
      + `K=${explanationParams.temporalKernel.toFixed(1)}`,
    source: 'secscore',
  });

  if (explanationParams.kev) {
    explanationEntries.push({
      title: 'CISA KEV',
      detail: `Applied KEV floor to ≥ ${KEV_MIN_FLOOR.toFixed(1)} after temporal kernel`,
      source: 'cisa-kev',
    });
  }

  const primaryExploitEvidence = explanationParams.exploits[0];
  if (primaryExploitEvidence) {
    const dateText: string = primaryExploitEvidence.publishedDate ? ` (published ${primaryExploitEvidence.publishedDate.split('T')[0]})` : '';
    explanationEntries.push({
      title: 'Exploit PoC',
      detail: `Added +${POC_BONUS_MAX.toFixed(1)} after temporal kernel from ExploitDB${dateText}`,
      source: 'exploitdb',
    });
  }

  if (explanationParams.epss) {
    const epssPercentile: number = Math.round(explanationParams.epss.percentile * 100);
    const epssBonus: number = EPSS_BLEND_WEIGHT * explanationParams.epss.score;
    explanationEntries.push({
      title: 'EPSS',
      detail: `Added +${epssBonus.toFixed(2)} (EPSS=${explanationParams.epss.score.toFixed(3)}, p${epssPercentile}) after temporal kernel`,
      source: 'epss',
    });
  }

  if (typeof explanationParams.cvssBase === 'number') {
    explanationEntries.push({
      title: 'CVSS Base',
      detail: `CVSS base score ${explanationParams.cvssBase.toFixed(1)} used for kernel`,
      source: 'cvss',
    });
  }
  else {
    explanationEntries.push({
      title: 'CVSS Missing',
      detail: 'CVSS base score unavailable; kernel defaults to 0',
      source: 'cvss',
    });
  }

  explanationEntries.push({
    title: 'SecScore',
    detail: `Final SecScore ${explanationParams.secscore.toFixed(1)}`,
    source: 'secscore',
  });

  return explanationEntries;
}
