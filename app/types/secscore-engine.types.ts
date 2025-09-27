import type { EpssSignal, ExploitEvidence } from '~/types/secscore.types';

export interface ExplanationParams {
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
