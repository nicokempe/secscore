import type { IncomingMessage } from 'node:http';
import type {
  GlobalWithUseRoute,
  Logger,
  LoggerEventContext,
  LoggerRouteInfo,
  LogLevel,
  LogMeta,
} from '~/types/logger.types';
import { formatConsoleLog, formatRemoteLogPayload } from '~/utils/formatters';

/** Priority mapping used to filter logs based on configured level. */
const logLevelPriority: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  success: 2,
  warn: 3,
  error: 4,
};

/**
 * Extracts contextual metadata from the current Nitro request.
 * Includes route, method, path, and request ID if available.
 */
function getContextMetadata(): LogMeta {
  if (!import.meta.server) {
    // Client side: we can only try to read the route name (optional).
    const globalWithRoute = globalThis as GlobalWithUseRoute;
    const route: LoggerRouteInfo | undefined = globalWithRoute.useRoute?.();
    const routeName: string | undefined = route?.name;
    return routeName ? { route: routeName } : {};
  }

  try {
    const event = useRequestEvent();
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
      }).catch((error: unknown): void => {
        const errorMessage: string = error instanceof Error ? error.message : String(error);
        formatConsoleLog('error', 'Remote logging failed', {
          error: errorMessage,
          url: remoteLogServerUrl,
        });
      });
    }
  }

  return {
    debug: (message: string, meta?: LogMeta): void => log('debug', message, meta),
    info: (message: string, meta?: LogMeta): void => log('info', message, meta),
    success: (message: string, meta?: LogMeta): void => log('success', message, meta),
    warn: (message: string, meta?: LogMeta): void => log('warn', message, meta),
    error: (message: string, meta?: LogMeta): void => log('error', message, meta),
  };
};
