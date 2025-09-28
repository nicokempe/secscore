/**
 * Shared logger-related type definitions used across the application.
 */
export type LogLevel = 'debug' | 'info' | 'success' | 'warn' | 'error';

export type LogMeta = Record<string, unknown>;

/** Optional context fields that may be attached to the Nitro event. */
export interface LoggerEventContext {
  requestId?: string
}

/** Narrow type for `useRoute()` when available on the client. */
export interface LoggerRouteInfo {
  name?: string
}

/** Global type that may expose `useRoute` on the client. */
export type GlobalWithUseRoute = typeof globalThis & {
  useRoute?: () => LoggerRouteInfo
};

// eslint-disable-next-line no-unused-vars -- named parameters improve generated documentation
type LoggerMethod = (message: string, meta?: LogMeta) => void;

/** Public logger interface exposing synchronous methods. */
export interface Logger {
  /** Log at debug level. */
  debug: LoggerMethod
  /** Log at info level. */
  info: LoggerMethod
  /** Log at success level. */
  success: LoggerMethod
  /** Log at warn level. */
  warn: LoggerMethod
  /** Log at error level. */
  error: LoggerMethod
}
