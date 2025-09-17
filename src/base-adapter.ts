import type {
  OAuthError,
  ProviderConfig,
} from './types.js';
import { ErrorNormalizer } from './utils/error-normalizer.js';

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
   * Creates a new BaseOAuthAdapter instance
   *
   * @param config - Provider-specific configuration including client credentials, scopes, and endpoints
   */
  public constructor(config: ProviderConfig) {
    this.config = config;
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
