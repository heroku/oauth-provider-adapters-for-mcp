import type { OAuthError } from '../types.js';
import createError from 'http-errors';
import { StatusCodes, ReasonPhrases } from 'http-status-codes';

/**
 * Error creation using http-errors for standardized error objects
 */
class ErrorBuilder {
  constructor(private httpError: any) {}

  withContext(context: { endpoint?: string; issuer?: string }): OAuthError {
    const result: OAuthError = {
      statusCode: this.httpError.statusCode,
      error: this.httpError.error || this.httpError.message,
    };

    if (this.httpError.error_description) {
      result.error_description = this.httpError.error_description;
    }
    if (context.endpoint !== undefined) {
      result.endpoint = context.endpoint;
    }
    if (context.issuer !== undefined) {
      result.issuer = context.issuer;
    }

    return result;
  }
}

/**
 * Build an error using http-errors
 */
function buildError(
  statusCode: number,
  error: string,
  description?: string
): ErrorBuilder {
  // http-errors deprecates non-4xx/5xx status codes; coerce to 500 in those cases
  const statusForHttpError =
    statusCode >= 400 && statusCode < 600
      ? statusCode
      : StatusCodes.INTERNAL_SERVER_ERROR;
  const httpError = createError(statusForHttpError, error, {
    error_description: description,
    error: error,
  });
  return new ErrorBuilder(httpError);
}

/**
 * Utility class for normalizing heterogeneous error shapes from HTTP libraries,
 * provider SDKs, and native errors into standardized OAuthError structures.
 */
export class ErrorNormalizer {
  /**
   * Normalize unknown error into standardized OAuthError structure
   */
  static normalizeError(
    e: unknown,
    context: { endpoint?: string; issuer?: string },
    defaultIssuer?: string
  ): OAuthError {
    const endpoint = context?.endpoint;
    const issuer = context?.issuer ?? defaultIssuer;

    // Build context object with only defined values
    const errorContext: { endpoint?: string; issuer?: string } = {};
    if (endpoint !== undefined) errorContext.endpoint = endpoint;
    if (issuer !== undefined) errorContext.issuer = issuer;

    // Try each error format in order of specificity
    return (
      this.tryOAuthErrorShape(e) ??
      this.tryAxiosErrorShape(e) ??
      this.tryFetchErrorShape(e) ??
      this.tryNativeErrorShape(e) ??
      this.tryStringErrorShape(e) ??
      this.createFallbackError()
    ).withContext(errorContext);
  }

  /**
   * Try parsing as existing OAuth error shape
   */
  private static tryOAuthErrorShape(e: unknown): ErrorBuilder | null {
    const obj = this.asObject(e);
    if (!obj) return null;

    const error = this.readString(obj, 'error');
    const statusCode =
      this.readNumber(obj, 'statusCode') ?? this.readNumber(obj, 'status');

    if (error && typeof statusCode === 'number') {
      const description =
        this.readString(obj, 'error_description') ??
        this.readString(obj, 'message');
      return buildError(statusCode, error, description);
    }
    return null;
  }

  /**
   * Try parsing as Axios-style error object with response wrapper
   */
  private static tryAxiosErrorShape(e: unknown): ErrorBuilder | null {
    const obj = this.asObject(e);
    if (!obj) return null;

    const response = this.asObject(
      (obj as Record<string, unknown>)['response']
    );
    if (!response) return null;

    const statusCode = this.readNumber(response, 'status');
    if (typeof statusCode !== 'number') return null;

    const data = this.asObject(response['data']);
    let error = data ? this.readString(data, 'error') : undefined;
    const description =
      (data && this.readString(data, 'error_description')) ||
      this.readString(response, 'statusText') ||
      this.getReasonPhrase(statusCode);

    if (!error) {
      error = this.mapStatusToOAuthError(statusCode);
    }

    return buildError(statusCode, error, description);
  }

  /**
   * Try parsing as Fetch/HTTP response object
   */
  private static tryFetchErrorShape(e: unknown): ErrorBuilder | null {
    const obj = this.asObject(e);
    if (!obj) return null;

    const statusCode = this.readNumber(obj, 'status');
    if (typeof statusCode !== 'number') return null;

    const description =
      this.readString(obj, 'statusText') || this.getReasonPhrase(statusCode);
    let error = this.readString(obj, 'error');

    if (!error) {
      error = this.mapStatusToOAuthError(statusCode);
    }

    return buildError(statusCode, error, description);
  }

  /**
   * Try parsing as native Error instance
   */
  private static tryNativeErrorShape(e: unknown): ErrorBuilder | null {
    if (!(e instanceof Error)) return null;

    let statusCode = StatusCodes.INTERNAL_SERVER_ERROR;
    let error = 'server_error';

    // Heuristic mapping using http-status-codes
    if (/timeout/i.test(e.message)) {
      error = 'temporarily_unavailable';
      statusCode = StatusCodes.GATEWAY_TIMEOUT;
    } else if (/network|fetch|ECONNREFUSED/i.test(e.message)) {
      error = 'server_error';
      statusCode = StatusCodes.SERVICE_UNAVAILABLE;
    } else if (/unauthorized|401/i.test(e.message)) {
      error = 'unauthorized';
      statusCode = StatusCodes.UNAUTHORIZED;
    } else if (/forbidden|403/i.test(e.message)) {
      error = 'access_denied';
      statusCode = StatusCodes.FORBIDDEN;
    }

    return buildError(statusCode, error, e.message);
  }

  /**
   * Try parsing as string primitive
   */
  private static tryStringErrorShape(e: unknown): ErrorBuilder | null {
    return typeof e === 'string'
      ? buildError(StatusCodes.INTERNAL_SERVER_ERROR, 'server_error', e)
      : null;
  }

  /**
   * Create fallback error for unrecognized shapes
   */
  private static createFallbackError(): ErrorBuilder {
    return buildError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'server_error',
      ReasonPhrases.INTERNAL_SERVER_ERROR
    );
  }

  /**
   * Map HTTP status codes to OAuth error codes using standardized mapping
   */
  private static mapStatusToOAuthError(statusCode: number): string {
    switch (statusCode) {
      case StatusCodes.BAD_REQUEST:
        return 'invalid_request';
      case StatusCodes.UNAUTHORIZED:
        return 'unauthorized';
      case StatusCodes.FORBIDDEN:
        return 'access_denied';
      case StatusCodes.NOT_FOUND:
        return 'invalid_request';
      case StatusCodes.TOO_MANY_REQUESTS:
        return 'temporarily_unavailable';
      case StatusCodes.INTERNAL_SERVER_ERROR:
      case StatusCodes.BAD_GATEWAY:
      case StatusCodes.SERVICE_UNAVAILABLE:
      case StatusCodes.GATEWAY_TIMEOUT:
        return 'server_error';
      default:
        return statusCode >= 500
          ? 'server_error'
          : statusCode >= 400
            ? 'invalid_request'
            : 'server_error';
    }
  }

  /**
   * Safely get reason phrase for HTTP status code
   */
  private static getReasonPhrase(statusCode: number): string {
    // Common HTTP status codes with their reason phrases
    const reasonPhrases: Record<number, string> = {
      [StatusCodes.BAD_REQUEST]: ReasonPhrases.BAD_REQUEST,
      [StatusCodes.UNAUTHORIZED]: ReasonPhrases.UNAUTHORIZED,
      [StatusCodes.FORBIDDEN]: ReasonPhrases.FORBIDDEN,
      [StatusCodes.NOT_FOUND]: ReasonPhrases.NOT_FOUND,
      [StatusCodes.INTERNAL_SERVER_ERROR]: ReasonPhrases.INTERNAL_SERVER_ERROR,
      [StatusCodes.BAD_GATEWAY]: ReasonPhrases.BAD_GATEWAY,
      [StatusCodes.SERVICE_UNAVAILABLE]: ReasonPhrases.SERVICE_UNAVAILABLE,
      [StatusCodes.GATEWAY_TIMEOUT]: ReasonPhrases.GATEWAY_TIMEOUT,
    };

    return reasonPhrases[statusCode] || `HTTP ${statusCode}`;
  }

  /**
   * Safe object casting utility
   */
  private static asObject(v: unknown): Record<string, unknown> | null {
    return v !== null && typeof v === 'object'
      ? (v as Record<string, unknown>)
      : null;
  }

  /**
   * Safe number property reader
   */
  private static readNumber(
    obj: Record<string, unknown> | null,
    key: string
  ): number | undefined {
    if (!obj) return undefined;
    const value = obj[key];
    return typeof value === 'number' ? value : undefined;
  }

  /**
   * Safe string property reader
   */
  private static readString(
    obj: Record<string, unknown> | null,
    key: string
  ): string | undefined {
    if (!obj) return undefined;
    const value = obj[key];
    return typeof value === 'string' ? value : undefined;
  }
}
