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
   */
  public abstract initialize(): Promise<void>;

  /**
   * Generate an authorization URL for starting the OAuth flow.
   *
   * @param interactionId - Correlation identifier for the auth interaction
   * @param redirectUrl - The redirect/callback URL to return to after consent
   * @returns A fully formed authorization URL
   */
  public abstract generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string>;

  /**
   * Exchange an authorization code for tokens.
   *
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
