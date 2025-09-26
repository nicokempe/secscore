export interface EpssSignal {
  score: number
  percentile: number
  fetchedAt: string
}

export interface ExploitEvidence {
  source: 'exploitdb'
  url: string | null
  publishedDate: string | null
}

export interface SecScoreResponse {
  cveId: string
  publishedDate: string | null
  cvssBase: number | null
  cvssVector: string | null
  secscore: number
  exploitProb: number
  modelCategory: string
  modelParams: { mu: number, lambda: number, kappa: number }
  epss: EpssSignal | null
  exploits: ExploitEvidence[]
  kev: boolean
  explanation: Array<{ title: string, detail: string, source: string }>
  computedAt: string
}
