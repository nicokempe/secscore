export interface NvdDescription {
  lang?: string
  value?: string
}

export interface NvdCvssData {
  baseScore?: number
  vectorString?: string
  score?: number
}

export interface NvdCvssMetric {
  cvssData?: NvdCvssData
  baseMetrics?: { baseScore?: number, score?: number, vectorString?: string }
}

export interface NvdCpeMatch {
  criteria?: string
}

export interface NvdConfigurationNode {
  cpeMatch?: NvdCpeMatch[]
  children?: NvdConfigurationNode[]
}

export interface NvdCve {
  id?: string
  published?: string
  descriptions?: NvdDescription[]
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[]
    cvssMetricV30?: NvdCvssMetric[]
    cvssMetricV3?: NvdCvssMetric[]
    cvssMetricV40?: NvdCvssMetric[]
    cvssMetricV2?: NvdCvssMetric[]
  }
  configurations?: { nodes?: NvdConfigurationNode[] }
}

export interface NvdVulnerability {
  cve?: NvdCve
}

export interface NvdResponse {
  vulnerabilities?: NvdVulnerability[]
}

export interface ExploitDbRecord {
  url?: string
  publishedDate?: string
  cveId?: string
}

export interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
  limit?: string
}

export interface OsvRange {
  type?: string
  events?: OsvEvent[]
}

export interface OsvPackage {
  ecosystem?: string
  name?: string
}

export interface OsvAffected {
  package?: OsvPackage
  ranges?: OsvRange[]
}

export interface OsvResponse {
  affected?: OsvAffected[]
}

export interface HttpErrorLike {
  statusCode: number
  message: string
}
