import { readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import type {
  KevCompactCandidate,
  KevCompactEntry,
  KevCompactFile,
  KevFullFile,
  KevMetaValue,
  KevRuntimeMetadata,
} from '~/types/kev.types';

const kevSet: Set<string> = new Set<string>();
const kevMeta: Map<string, KevMetaValue> = new Map<string, KevMetaValue>();
let currentEtag: string | undefined;
let currentLastModified: string | undefined;
let currentUpdatedAt: string | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function toStringOrUndefined(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeCompactEntry(value: unknown): KevCompactEntry | null {
  if (!isRecord(value)) {
    return null;
  }
  const cveIdCandidate = toStringOrUndefined(value.cveId ?? value.cveID);
  if (!cveIdCandidate) {
    return null;
  }
  const entry: KevCompactEntry = { cveId: cveIdCandidate };
  const dateAdded = toStringOrUndefined(value.dateAdded);
  if (dateAdded) {
    entry.dateAdded = dateAdded;
  }
  const vendorProject = toStringOrUndefined(value.vendorProject);
  if (vendorProject) {
    entry.vendorProject = vendorProject;
  }
  const product = toStringOrUndefined(value.product);
  if (product) {
    entry.product = product;
  }
  return entry;
}

function normalizeFromVulnerabilities(payload: KevFullFile): KevCompactEntry[] {
  const raw = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];
  const items: KevCompactEntry[] = [];
  const seen = new Set<string>();
  for (const candidate of raw) {
    const entry = normalizeCompactEntry(candidate);
    if (!entry) {
      continue;
    }
    if (seen.has(entry.cveId)) {
      continue;
    }
    seen.add(entry.cveId);
    items.push(entry);
  }
  return items;
}

function normalizeFromCompact(payload: KevCompactCandidate): KevCompactFile {
  const updatedAt = toStringOrUndefined(payload.updatedAt) ?? new Date().toISOString();
  const itemsRaw = Array.isArray(payload.items) ? payload.items : [];
  const items: KevCompactEntry[] = [];
  const seen = new Set<string>();
  for (const candidate of itemsRaw) {
    const entry = normalizeCompactEntry(candidate);
    if (!entry || seen.has(entry.cveId)) {
      continue;
    }
    seen.add(entry.cveId);
    items.push(entry);
  }
  return {
    etag: toStringOrUndefined(payload.etag),
    lastModified: toStringOrUndefined(payload.lastModified),
    updatedAt,
    items,
  };
}

export function buildCompactFromFull(payload: unknown): KevCompactFile {
  if (isRecord(payload) && 'items' in payload) {
    return normalizeFromCompact(payload as KevCompactCandidate);
  }
  if (isRecord(payload) && 'vulnerabilities' in payload) {
    const items = normalizeFromVulnerabilities(payload as KevFullFile);
    return {
      updatedAt: new Date().toISOString(),
      items,
    };
  }
  throw new Error('Invalid KEV payload');
}

export function hydrateRuntime(compact: KevCompactFile): void {
  kevSet.clear();
  kevMeta.clear();
  for (const item of compact.items) {
    kevSet.add(item.cveId);
    kevMeta.set(item.cveId, {
      dateAdded: item.dateAdded,
      vendorProject: item.vendorProject,
      product: item.product,
    });
  }
  currentEtag = compact.etag;
  currentLastModified = compact.lastModified;
  currentUpdatedAt = compact.updatedAt;
}

export function getKevSet(): ReadonlySet<string> {
  return kevSet;
}

export function getKevMetaMap(): ReadonlyMap<string, KevMetaValue> {
  return kevMeta;
}

export function getRuntimeMetadata(): KevRuntimeMetadata {
  return {
    etag: currentEtag,
    lastModified: currentLastModified,
    updatedAt: currentUpdatedAt,
  };
}

export function loadCompactFromDisk(path: string): KevCompactFile | null {
  try {
    const fileContents = readFileSync(path, 'utf8');
    const parsed = JSON.parse(fileContents) as unknown;
    return buildCompactFromFull(parsed);
  }
  catch {
    return null;
  }
}

export async function saveCompactToDisk(path: string, compact: KevCompactFile): Promise<void> {
  const serialized = JSON.stringify(compact, null, 2);
  await writeFile(path, `${serialized}\n`, 'utf8');
}
