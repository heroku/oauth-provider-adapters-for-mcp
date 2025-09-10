import type {
  OAuthError,
  ProviderConfig,
  ProviderQuirks,
  TokenResponse,
} from './types.js';
import { ErrorNormalizer } from './utils/error-normalizer.js';

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
   * Tracks whether the adapter has been initialized
   */
  private _initialized = false;

  /**
   * Creates a new BaseOAuthAdapter instance
   *
   * @param config - Provider-specific configuration including client credentials, scopes, and endpoints
   */
  public constructor(config: ProviderConfig) {
    if (new.target === BaseOAuthAdapter) {
      throw new TypeError(
        'BaseOAuthAdapter is abstract and cannot be instantiated directly'
      );
    }
    this.config = config;
  }

  /**
   * Initialize provider-specific resources.
   * Subclasses should perform any discovery, validation or setup work here.
   * Must call super.initialize() to mark the adapter as initialized.
   */
  public async initialize(): Promise<void> {
    this._initialized = true;
  }

  /**
   * Generate an authorization URL for starting the OAuth flow.
   *
   * @param interactionId - Correlation identifier for the auth interaction
   * @param redirectUrl - The redirect/callback URL to return to after consent
   * @returns A fully formed authorization URL
   * @throws {OAuthError} If the adapter has not been initialized
   */
  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
    if (!this._initialized) {
      throw this.normalizeError(
        new Error('Adapter must be initialized before generating auth URL'),
        { endpoint: 'generateAuthUrl' }
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
   * Return provider-specific capability flags and quirks.
   */
  public abstract getProviderQuirks(): ProviderQuirks;

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
