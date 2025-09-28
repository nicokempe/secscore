import { describe, expect, it } from 'vitest';

import { EPSS_BLEND_WEIGHT, KEV_MIN_FLOOR, POC_BONUS_MAX } from '../../server/lib/constants';
import {
  asymmetricLaplaceCdf,
  buildExplanation,
  computeSecScore,
  inferCategory,
} from '../../server/lib/secscore-engine';

describe('inferCategory', (): void => {
  it('returns "default" when list is empty or missing', (): void => {
    expect(inferCategory([])).toBe('default');
  });

  it('detects specific ecosystems and platforms', (): void => {
    const cases: Array<{ expected: string, cpes: string[] }> = [
      { expected: 'php', cpes: ['cpe:/a:php:php:8.1'] },
      { expected: 'webapps', cpes: ['cpe:/a:wordpress:wordpress:6.4'] },
      { expected: 'windows', cpes: ['cpe:/o:microsoft:windows_11:-'] },
      { expected: 'linux', cpes: ['cpe:/o:linux:linux_kernel:6.8'] },
      { expected: 'android', cpes: ['cpe:/o:google:android:15'] },
      { expected: 'ios', cpes: ['cpe:/o:apple:iphone_os:17'] },
      { expected: 'macos', cpes: ['cpe:/o:apple:mac_os_x:14'] },
      { expected: 'java', cpes: ['cpe:/a:oracle:java:8'] },
      { expected: 'dos', cpes: ['cpe:/a:vendor:product:1.0::denial_of_service'] },
      { expected: 'asp', cpes: ['cpe:/a:vendor:aspnet_core:8.0'] },
      { expected: 'hardware', cpes: ['cpe:/h:vendor:router_firmware:1.0'] },
      { expected: 'remote', cpes: ['cpe:/a:vendor:product:1.0:remote'] },
      { expected: 'local', cpes: ['cpe:/a:vendor:product:1.0:local'] },
    ];

    for (const testCase of cases) {
      expect(inferCategory(testCase.cpes)).toBe(testCase.expected);
    }
  });

  it('prioritizes PHP ecosystems when multiple categories match', (): void => {
    expect(
      inferCategory([
        'cpe:/o:microsoft:windows_server:2022',
        'cpe:/a:php:php:8.2',
      ]),
    ).toBe('php');
  });
});

describe('asymmetricLaplaceCdf', (): void => {
  it('returns 0 when inputs are not finite numbers', (): void => {
    expect(asymmetricLaplaceCdf(Number.NaN, 1, 1, 1)).toBe(0);
    expect(asymmetricLaplaceCdf(5, Number.POSITIVE_INFINITY, 1, 1)).toBe(0);
  });

  it('evaluates the lower-tail branch when weeks are before the mode', (): void => {
    const result: number = asymmetricLaplaceCdf(2, 4, 0.5, 1.2);
    expect(result).toBeCloseTo(0.256, 3);
  });

  it('evaluates the upper-tail branch when weeks exceed the mode', () => {
    const result: number = asymmetricLaplaceCdf(6, 4, 0.5, 1.2);
    expect(result).toBeCloseTo(0.877, 3);
  });
});

describe('computeSecScore', (): void => {
  it('combines CVSS, temporal multipliers, and exploit probability', (): void => {
    const result = computeSecScore({
      cvssBase: 7.5,
      cvssVector: null,
      cvssVersion: '3.1',
      exploitProb: 0.5,
      kev: false,
      hasExploit: false,
      epss: null,
      temporalMultipliers: {
        remediationLevel: 0.95,
        reportConfidence: 0.96,
      },
    });

    expect(result.secscore).toBe(6.5);
    expect(result.temporalKernel).toBe(6.8);
    expect(result.exploitMaturity).toBeCloseTo(0.955, 10);
    expect(result.eMin).toBeCloseTo(0.91, 10);
  });

  it('enforces the KEV minimum floor when applicable', (): void => {
    const result = computeSecScore({
      cvssBase: 1,
      cvssVector: null,
      cvssVersion: '3.1',
      exploitProb: 0,
      kev: true,
      hasExploit: false,
      epss: null,
    });

    expect(result.secscore).toBe(KEV_MIN_FLOOR);
    expect(result.temporalKernel).toBe(1);
    expect(result.exploitMaturity).toBeCloseTo(0.91, 10);
    expect(result.eMin).toBeCloseTo(0.91, 10);
  });

  it('incorporates CVSS v4 exploitability, EPSS, and exploit bonuses', (): void => {
    const result = computeSecScore({
      cvssBase: 4,
      cvssVector: 'CVSS:4.0/AV:N',
      cvssVersion: '4.0',
      exploitProb: 0.2,
      kev: false,
      hasExploit: true,
      epss: {
        score: 0.42,
        percentile: 0.9,
        fetchedAt: '2024-01-01T00:00:00Z',
      },
    });

    expect(result.secscore).toBe(5.7);
    expect(result.temporalKernel).toBe(4);
    expect(result.exploitMaturity).toBeCloseTo(0.92, 10);
    expect(result.eMin).toBeCloseTo(0.9, 10);
  });
});

describe('buildExplanation', (): void => {
  it('includes contextual details for all contributing signals', (): void => {
    const explanation = buildExplanation({
      kev: true,
      exploits: [
        {
          source: 'exploitdb',
          url: 'https://www.exploit-db.com/exploits/12345',
          publishedDate: '2024-05-01T12:34:56Z',
        },
      ],
      epss: {
        score: 0.42,
        percentile: 0.9,
        fetchedAt: '2024-01-01T00:00:00Z',
      },
      exploitProb: 0.37,
      modelCategory: 'linux',
      modelParams: { mu: 3.2, lambda: 0.8, kappa: 1.1 },
      tWeeks: 5.5,
      cvssBase: 7.2,
      secscore: 8.4,
      temporalKernel: 6.3,
      temporalExploitMaturity: 0.95,
    });

    expect(explanation).toHaveLength(6);
    expect(explanation[0]).toEqual({
      title: 'Temporal model',
      detail:
        'category=linux, mu=3.20, lambda=0.80, kappa=1.10, tWeeks=5.50, exploitProb=0.370, E_S(t)=0.950, K=6.3',
      source: 'secscore',
    });
    expect(explanation[1]).toEqual({
      title: 'CISA KEV',
      detail: `Applied KEV floor to ≥ ${KEV_MIN_FLOOR.toFixed(1)} after temporal kernel`,
      source: 'cisa-kev',
    });
    expect(explanation[2]).toEqual({
      title: 'Exploit PoC',
      detail: `Added +${POC_BONUS_MAX.toFixed(1)} after temporal kernel from ExploitDB (published 2024-05-01)`,
      source: 'exploitdb',
    });
    expect(explanation[3]).toEqual({
      title: 'EPSS',
      detail: `Added +${(EPSS_BLEND_WEIGHT * 0.42).toFixed(2)} (EPSS=0.420, p90) after temporal kernel`,
      source: 'epss',
    });
    expect(explanation[4]).toEqual({
      title: 'CVSS Base',
      detail: 'CVSS base score 7.2 used for kernel',
      source: 'cvss',
    });
    expect(explanation[5]).toEqual({
      title: 'SecScore',
      detail: 'Final SecScore 8.4',
      source: 'secscore',
    });
  });

  it('falls back to CVSS missing messaging when base score is unavailable', (): void => {
    const explanation = buildExplanation({
      kev: false,
      exploits: [],
      epss: null,
      exploitProb: 0.12,
      modelCategory: 'default',
      modelParams: { mu: 2.5, lambda: 0.6, kappa: 1 },
      tWeeks: 1.5,
      cvssBase: null,
      secscore: 0.4,
      temporalKernel: 0.7,
      temporalExploitMaturity: 0.5,
    });

    expect(explanation).toHaveLength(3);
    expect(explanation[1]).toEqual({
      title: 'CVSS Missing',
      detail: 'CVSS base score unavailable; kernel defaults to 0',
      source: 'cvss',
    });
    expect(explanation[2]).toEqual({
      title: 'SecScore',
      detail: 'Final SecScore 0.4',
      source: 'secscore',
    });
  });
});
