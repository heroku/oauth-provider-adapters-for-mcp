import type {
  OAuthError,
  ProviderConfig,
  ProviderQuirks,
  TokenResponse,
} from './types.js';
import { ErrorNormalizer } from './utils/error-normalizer.js';
import { Logger } from './logging/types.js';
import { DefaultLogger } from './logging/logger.js';

/**
 * Abstract base class that all OAuth provider adapters must implement.
 * Establishes the core contract for initialization, authorization URL generation,
 * token exchange, refresh, and provider quirks metadata.
 */
export abstract class BaseOAuthAdapter {
  /**
   * Provider configuration stored as protected readonly for subclass access
   */
  protected readonly config: ProviderConfig;

  /**
   * Memoized cache of computed provider quirks
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
   */
  public constructor(config: ProviderConfig) {
    this.config = config;
  }

  public get logger(): Logger {
    if (this.loggerImpl === null || this.loggerImpl === undefined) {
      this.loggerImpl = new DefaultLogger(
        { clientId: this.config.clientId },
        { redactPaths: ['clientSecret'] }
      );
    }
    return this.loggerImpl;
  }

  /**
   * Initialize provider-specific resources.
   * Subclasses must implement this to perform any discovery, validation or setup work.
   * This method should be called before using any other adapter methods.
   */
  public abstract initialize(): Promise<void>;

  /**
   * Generate an authorization URL for starting the OAuth flow.
   *
   * @param interactionId - Correlation identifier for the auth interaction
   * @param redirectUrl - The redirect/callback URL to return to after consent
   * @returns A fully formed authorization URL
   */
  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
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
   * Compute provider-specific capability flags and quirks.
   * Implementations MUST NOT perform network I/O.
   */
  protected abstract computeProviderQuirks(): ProviderQuirks;

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
   * Exchange an authorization code for tokens.
   *
   * Subclasses are responsible for:
   * - Mapping provider-specific token payloads into a normalized {@link TokenResponse}
   *   (e.g., access_token -> accessToken, refresh_token -> refreshToken, id_token -> idToken,
   *   expires_in -> expiresIn, scope -> scope)
   * - Catching unknown/provider errors and re-throwing a normalized {@link OAuthError}
   *   via the protected {@link normalizeError} helper with an appropriate context
   *   (e.g., endpoint: '/token')
   * @param code - The authorization code received from the provider
   * @param verifier - PKCE code verifier used during authorization
   * @param redirectUrl - The same redirect URL used to obtain the code
   * @returns A normalized token response
   */
  public abstract exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse>;

  /**
   * Refresh tokens using a refresh token.
   *
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
   */
  public getProviderQuirks(): ProviderQuirks {
    if (!this.providerQuirksCache) {
      this.providerQuirksCache = this.computeProviderQuirks();
    }
    return this.providerQuirksCache;
  }

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
}
