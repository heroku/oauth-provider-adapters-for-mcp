import type {
  OAuthError,
  ProviderConfig,
  TokenResponse,
  ProviderQuirks,
} from './types.js';
import { ErrorNormalizer } from './utils/error-normalizer.js';
import {
  ResilienceManager,
  type ResilienceContext,
} from './utils/resilience-manager.js';
import { Logger } from './logging/types.js';
import { DefaultLogger } from './logging/logger.js';

const MCP_OAUTH_REDACTION_PATHS = [
  // Direct fields
  'clientSecret',
  'accessToken',
  'refreshToken',

  // HTTP error contexts (predictable depth)
  'response.data.access_token',
  'response.data.client_secret',
  'request.headers.authorization',

  // Token endpoint responses
  'body.access_token',
  'data.refresh_token',

  // Provider metadata
  'metadata.client_secret',
  'config.clientSecret',
];

/**
 * Abstract base class that all OAuth provider adapters must implement.
 * Establishes the core contract for initialization, authorization URL generation,
 * token exchange, and refresh.
 */
export abstract class BaseOAuthAdapter {
  /**
   * Provider configuration stored as protected readonly for subclass access
   */
  protected readonly config: ProviderConfig;

  /**
   * Initialization state tracking
   */
  protected initialized = false;

  /**
   * Provider quirks cache for lazy memoization
   */
  private providerQuirksCache?: ProviderQuirks;

  /**
   * Stores our lazily instantiated implementation of Logger.
   */
  private loggerImpl?: Logger;

  /**
   * Creates a new BaseOAuthAdapter instance
   *
   * @param config - Provider-specific configuration including client credentials, scopes, and endpoints
   * @param logger - Optional logger instance to use instead of default logger
   */
  public constructor(config: ProviderConfig, logger?: Logger) {
    this.config = config;
    if (logger) {
      this.loggerImpl = logger;
    }
  }

  public get logger(): Logger {
    if (this.loggerImpl === null || this.loggerImpl === undefined) {
      this.loggerImpl = new DefaultLogger(
        { clientId: this.config.clientId },
        { redactPaths: MCP_OAUTH_REDACTION_PATHS }
      );
    }
    return this.loggerImpl;
  }

  /**
   * Set a custom logger instance for this adapter
   * @param logger - The logger instance to use
   */
  public setLogger(logger: Logger): void {
    this.loggerImpl = logger;
  }

  /**
   * Initialize provider-specific resources.
   * Subclasses must implement this to perform any discovery, validation or setup work.
   * This method should be called before using any other adapter methods.
   * Subclasses should set this.initialized = true upon successful initialization.
   */
  public abstract initialize(): Promise<void>;

  /**
   * Generate an authorization URL for starting the OAuth flow.
   *
   * @param interactionId - Correlation identifier for the auth interaction
   * @param redirectUrl - The redirect/callback URL to return to after consent
   * @returns A fully formed authorization URL
   * @throws OAuthError if adapter is not initialized
   */
  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
    if (!this.initialized) {
      throw this.normalizeError(
        new Error('Adapter not initialized. Call initialize() first.'),
        { endpoint: '/authorize' }
      );
    }

    const authEndpoint = this.getAuthorizationEndpoint();
    const baseParams = this.buildBaseAuthParams(interactionId, redirectUrl);
    const customParams = this.config.customParameters || {};

    // Merge custom parameters with base parameters
    const allParams = { ...baseParams, ...customParams };

    return this.buildAuthorizeUrl(authEndpoint, allParams);
  }

  /**
   * Get the authorization endpoint URL from provider metadata.
   * Subclasses must implement this to provide the correct endpoint.
   */
  protected abstract getAuthorizationEndpoint(): string;

  /**
   * Build base authorization parameters for the OAuth flow.
   *
   * @param interactionId - Correlation identifier for the auth interaction
   * @param redirectUrl - The redirect/callback URL to return to after consent
   * @returns Base parameters object
   */
  protected buildBaseAuthParams(
    interactionId: string,
    redirectUrl: string
  ): Record<string, string> {
    return {
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUrl,
      scope: this.config.scopes.join(' '),
      state: interactionId,
    };
  }

  /**
   * Build a complete authorization URL with query parameters.
   *
   * @param endpoint - The authorization endpoint URL
   * @param params - Query parameters to include
   * @returns Complete authorization URL
   */
  protected buildAuthorizeUrl(
    endpoint: string,
    params: Record<string, string>
  ): string {
    const url = new URL(endpoint);

    // Add all parameters as query string
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });

    return url.toString();
  }

  /**
   * Exchange authorization code for access token.
   * Subclasses must implement this to handle the OAuth token exchange flow.
   *
   * @param code - Authorization code from the callback
   * @param verifier - PKCE code verifier (if using PKCE)
   * @param redirectUrl - The redirect URL used in the authorization request
   * @returns Normalized token response
   */
  public abstract exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse>;

  /**
   * Refresh an access token using a refresh token.
   * Subclasses are responsible for:
   * - Performing the provider refresh request (if supported) and mapping the result
   *   into a normalized {@link TokenResponse}
   * - If refresh is not supported by the provider, throwing a normalized {@link OAuthError}
   *   (e.g., statusCode 400 with error 'unsupported_grant_type') using {@link normalizeError}
   * - Catching unknown/provider errors and re-throwing a normalized {@link OAuthError}
   *   via {@link normalizeError} with context (e.g., endpoint: '/token')
   * @param refreshToken - The refresh token to exchange
   * @returns A normalized token response
   */
  public abstract refreshToken(refreshToken: string): Promise<TokenResponse>;

  /**
   * Return provider-specific capability flags and quirks. Lazily memoizes
   * the result of {@link computeProviderQuirks}. This method performs no
   * network I/O.
   *
   * @returns Provider quirks object
   */
  public getProviderQuirks(): ProviderQuirks {
    if (!this.providerQuirksCache) {
      this.providerQuirksCache = this.computeProviderQuirks();
    }
    return this.providerQuirksCache;
  }

  /**
   * Compute provider-specific capabilities and requirements.
   * Subclasses must implement this to return provider quirks.
   * This method should perform no network I/O.
   *
   * @returns Provider quirks object
   */
  protected abstract computeProviderQuirks(): ProviderQuirks;

  /**
   * Normalize heterogeneous error shapes from HTTP libraries, provider SDKs,
   * and native errors into a standardized OAuthError structure.
   *
   * This method is intended to be reused by subclasses at network and SDK
   * boundaries to ensure consistent error handling and logging.
   *
   * @param e - Unknown error thrown by dependencies
   * @param context - Additional context such as endpoint or issuer
   * @returns Normalized {@link OAuthError}
   */
  protected normalizeError(
    e: unknown,
    context: { endpoint?: string; issuer?: string }
  ): OAuthError {
    return ErrorNormalizer.normalizeError(e, context, this.config.issuer);
  }

  /**
   * Enforce production storage safety by preventing unsafe fallbacks to in-memory storage.
   * This generic method can be used by any adapter that needs persistent storage.
   *
   * @param storageHook - The storage hook implementation (or undefined)
   * @param hookName - Name of the hook for error/logging messages
   * @param mockFallback - Function to create mock storage for development
   * @returns The storage hook to use
   * @throws {OAuthError} If no storage hook is provided in production
   */
  protected enforceProductionStorage<T>(
    storageHook: T | undefined,
    hookName: string,
    mockFallback: () => T
  ): T {
    if (!storageHook) {
      if (process.env.NODE_ENV === 'production') {
        throw this.normalizeError(
          new Error(
            `Persistent ${hookName} is required in production; in-memory storage is not allowed`
          ),
          { endpoint: 'initialize' }
        );
      }
      this.logger.warn(
        `No ${hookName} provided; using in-memory mock storage (not for production)`,
        { stage: 'initialize' }
      );
      return mockFallback();
    }
    return storageHook;
  }

  /**
   * Create a standardized OAuth error with consistent structure.
   * Helper method for subclasses to create well-formed errors.
   *
   * @param error - OAuth error code
   * @param description - Human-readable error description
   * @param context - Additional context like stage, endpoint, issuer
   * @returns Normalized OAuthError
   */
  protected createStandardError(
    error: string,
    description: string,
    context: { endpoint?: string; stage?: string; issuer?: string }
  ): OAuthError {
    return this.normalizeError(
      { error, error_description: description, statusCode: 400 },
      context
    );
  }

  /**
   * Execute an operation with resilience patterns: retry with exponential backoff and circuit breaker.
   * This method provides consistent error handling and reliability for OAuth provider endpoint calls.
   *
   * @param operation - The async operation to execute
   * @param context - Context for the operation including endpoint and resilience configuration
   * @returns The result of the operation
   * @throws {OAuthError} If operation fails after retries or circuit is open
   */
  protected async executeWithResilience<T>(
    operation: () => Promise<T>,
    context: ResilienceContext
  ): Promise<T> {
    return ResilienceManager.executeWithResilience(
      operation,
      context,
      (error, errorContext) => this.normalizeError(error, errorContext)
    );
  }

  /**
   * Set HTTP defaults for network operations.
   * This method can be called by subclasses to configure timeouts and other HTTP settings.
   *
   * @param options - HTTP configuration options
   */
  protected setHttpDefaults(options: {
    timeout?: number;
    [key: string]: unknown;
  }): void {
    // This is a placeholder - subclasses should override this if they need to set HTTP defaults
    // For example, an OIDC adapter may use openid-client's HTTP configuration mechanisms if available.
    this.logger.debug('HTTP defaults set', { options, stage: 'http-config' });
  }
}
