/**
 * Returns true when the provided value is `null`, `undefined`, or a blank string after trimming.
 */
export function isMissing(value: unknown): boolean {
  if (value === null || value === undefined) {
    return true;
  }

  if (typeof value === 'string') {
    return value.trim().length === 0;
  }

  return false;
}

/**
 * Validates whether the supplied string is a properly formatted CVE identifier.
 */
export function isValidCve(value: string): boolean {
  const pattern = /^CVE-\d{4}-\d{4,}$/u;
  return pattern.test(value);
}
