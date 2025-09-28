// ─────────────────────────────────────────────────────────────
// Logging helpers
// ─────────────────────────────────────────────────────────────

export type LogLevel = 'debug' | 'info' | 'success' | 'warn' | 'error';
export type LogMeta = Record<string, unknown>;

const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const WHITE = '\x1b[37m';
const RESET_COLOR = '\x1b[0m';

const colorForLevel: Record<LogLevel, string> = {
  debug: WHITE,
  info: WHITE,
  success: GREEN,
  warn: YELLOW,
  error: RED,
};

const shortLabels: Record<LogLevel, string> = {
  debug: 'DEBG',
  info: 'INFO',
  success: 'DONE',
  warn: 'WARN',
  error: 'FAIL',
};

/**
 * Format and print a log line to the local console.
 */
export function formatConsoleLog(level: LogLevel, message: string, meta?: LogMeta): void {
  const now: Date = new Date();
  const timestamp: string = `${now.toLocaleDateString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })} | ${now.toLocaleTimeString('de-DE', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })}`;

  const label: string = shortLabels[level];
  const hasMeta: boolean = !!meta && Object.keys(meta).length > 0;
  const metaStr: string = hasMeta ? ` ${JSON.stringify(meta, null, 2)}` : '';

  if (import.meta.server) {
    const color: string = colorForLevel[level];
    console.log(`[${CYAN}${timestamp}${RESET_COLOR}] ${color}${label}${RESET_COLOR} | ${message}${metaStr}`);
  }
  else {
    const levelStyle: Record<LogLevel, string> = {
      debug: 'color: gray',
      info: 'color: white',
      success: 'color: green',
      warn: 'color: orange',
      error: 'color: red',
    };
    const style: string = levelStyle[level];
    console.log(`[%c${timestamp}%c] %c${label}%c | ${message}`, 'color: #0aa;', '', style, '', meta ?? '');
  }
}

interface RemoteLogPayload {
  streams: Array<{
    stream: {
      level: LogLevel
      service: string
      env: string
    }
    values: [string, string][]
  }>
}

/**
 * Build a remote log payload compatible with Grafana Loki-style endpoints.
 */
export function formatRemoteLogPayload(level: LogLevel, message: string, meta?: LogMeta): RemoteLogPayload {
  return {
    streams: [
      {
        stream: {
          level,
          service: 'DashioDevs/website',
          env: process.env.NODE_ENV || 'unknown',
        },
        values: [[`${Date.now() * 1_000_000}`, JSON.stringify({ message, ...meta })]],
      },
    ],
  };
}
