export interface KevCompactEntry {
  cveId: string
  dateAdded?: string
  vendorProject?: string
  product?: string
}

export interface KevCompactFile {
  etag?: string
  lastModified?: string
  updatedAt: string
  items: KevCompactEntry[]
}

export interface KevMetaValue {
  dateAdded?: string
  vendorProject?: string
  product?: string
}

export interface KevRuntimeMetadata {
  etag?: string
  lastModified?: string
  updatedAt?: string
}

export interface KevFullFile {
  vulnerabilities?: unknown
}

export interface KevCompactCandidate {
  etag?: unknown
  lastModified?: unknown
  updatedAt?: unknown
  items?: unknown
}

export interface KevStatus {
  count: number
  updatedAt?: string
  etag?: string
  lastModified?: string
}

export interface KevRefreshResult {
  changed: boolean
  count: number
  updatedAt: string
}
