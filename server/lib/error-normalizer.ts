import { H3Error } from 'h3';

interface NormalizedError {
  statusCode: number
  message: string
  details?: unknown
}

const DEFAULT_ERROR_MESSAGE = 'Internal Server Error';

/**
 * Normalizes thrown values into structured HTTP-friendly errors while emitting structured JSON logs.
 */
export function normalizeServerError(error: unknown): NormalizedError {
  let statusCode = 500;
  let message = DEFAULT_ERROR_MESSAGE;
  let details: unknown;
  let errorType = 'UnknownError';

  if (error instanceof H3Error) {
    statusCode = error.statusCode ?? 500;
    message = error.message;
    details = error.data;
    errorType = error.constructor.name;
  }
  else if (error instanceof Error) {
    message = error.message || DEFAULT_ERROR_MESSAGE;
    details = { stack: error.stack };
    errorType = error.constructor.name;
  }
  else if (typeof error === 'object' && error !== null && 'statusCode' in (error as Record<string, unknown>)) {
    const maybeError = error as { statusCode?: number, message?: string };
    statusCode = maybeError.statusCode ?? 500;
    message = maybeError.message ?? DEFAULT_ERROR_MESSAGE;
    errorType = 'HttpErrorLike';
  }
  else if (typeof error === 'object' && error !== null) {
    message = 'Unexpected error object';
    details = error;
    errorType = 'ObjectError';
  }
  else if (typeof error === 'string') {
    message = error;
    errorType = 'StringError';
  }

  const logPayload = {
    time: new Date().toISOString(),
    level: 'error' as const,
    msg: message,
    errorType,
    context: details ?? null,
  };

  console.log(JSON.stringify(logPayload));

  return { statusCode, message, details };
}
