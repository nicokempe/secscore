import type { IncomingMessage } from 'node:http';
import type { H3Event } from 'h3';
import type { LogLevel, LogMeta } from '~/utils/formatters';
import { formatConsoleLog, formatRemoteLogPayload } from '~/utils/formatters';

/** Priority mapping used to filter logs based on configured level. */
const logLevelPriority: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  success: 2,
  warn: 3,
  error: 4,
};

/** Optional context fields we might attach in Nitro. */
interface LoggerEventContext {
  requestId?: string
}

/** Narrow type for `useRoute()` when available on client. */
interface MaybeRoute {
  name?: string
}

/** Global type that may expose `useRoute` on the client. */
type GlobalWithUseRoute = typeof globalThis & {
  useRoute?: () => MaybeRoute
};

/**
 * Extracts contextual metadata from the current Nitro request.
 * Includes route, method, path, and request ID if available.
 */
function getContextMetadata(): LogMeta {
  if (!import.meta.server) {
    // Client side: we can only try to read the route name (optional).
    const routeName: string | undefined = (globalThis as GlobalWithUseRoute).useRoute?.()?.name;
    return routeName ? { route: routeName } : {};
  }

  try {
    // `useRequestEvent()` returns `H3Event | undefined`.
    const event = useRequestEvent() as H3Event | undefined;
    if (!event) return {};

    // Read HTTP method safely.
    const req: IncomingMessage | undefined = event.node?.req as IncomingMessage | undefined;
    const method: string | undefined = req?.method;

    // `event.path` is a string on server.
    const path: string | undefined = event.path;

    // Pull a typed `requestId` if your app attaches it to `event.context`.
    // Context is untyped, so we narrow it safely without `any`.
    const requestId: string | undefined = (event.context as LoggerEventContext | undefined)?.requestId;

    const context: LogMeta = {};
    if (requestId) context.requestId = requestId;
    if (method) context.method = method;
    if (path) context.path = path;

    return context;
  }
  catch {
    return {};
  }
}

/** Public logger interface exposing synchronous methods. */
export interface Logger {
  /** Log at debug level. */
  debug: (message: string, meta?: LogMeta) => void
  /** Log at info level. */
  info: (message: string, meta?: LogMeta) => void
  /** Log at success level. */
  success: (message: string, meta?: LogMeta) => void
  /** Log at warn level. */
  warn: (message: string, meta?: LogMeta) => void
  /** Log at error level. */
  error: (message: string, meta?: LogMeta) => void
}

/**
 * Logger composable that logs to console and (optionally) a remote endpoint.
 *
 * - Public API is **synchronous** (returns `void`) to avoid “floating Promise” issues.
 * - Remote logging is fired-and-forgotten and errors are routed through `logNormalizedError`.
 */
export const useLogger = (): Logger => {
  const {
    public: {
      logging: { logLevel, remoteLoggingEnabled, remoteLogServerUrl },
    },
  } = useRuntimeConfig() as {
    public: {
      logging: {
        logLevel: LogLevel
        remoteLoggingEnabled: boolean
        remoteLogServerUrl: string
      }
    }
  };

  const currentLevel: number = logLevelPriority[logLevel ?? 'info'];

  /**
   * Central log routine. Non-async by design.
   */
  function log(level: LogLevel, message: string, meta: LogMeta = {}): void {
    if (logLevelPriority[level] < currentLevel) return;

    const combinedMeta: LogMeta = { ...getContextMetadata(), ...meta };
    formatConsoleLog(level, message, combinedMeta);

    if (remoteLoggingEnabled && remoteLogServerUrl.length > 0) {
      // Fire-and-forget; capture errors centrally.
      void $fetch(remoteLogServerUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: formatRemoteLogPayload(level, message, combinedMeta),
      }).catch((err: unknown): void => {
        console.error('Remote logging failed: ', err);
      });
    }
  }

  return {
    debug: (msg: string, meta?: LogMeta): void => log('debug', msg, meta),
    info: (msg: string, meta?: LogMeta): void => log('info', msg, meta),
    success: (msg: string, meta?: LogMeta): void => log('success', msg, meta),
    warn: (msg: string, meta?: LogMeta): void => log('warn', msg, meta),
    error: (msg: string, meta?: LogMeta): void => log('error', msg, meta),
  };
};
