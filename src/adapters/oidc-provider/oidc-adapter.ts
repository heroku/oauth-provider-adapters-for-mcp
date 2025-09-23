/**
 * OIDC Provider Adapter implementation
 * Extends BaseOAuthAdapter to provide OIDC-specific functionality
 */

import { BaseOAuthAdapter } from '../../base-adapter.js';
import type { OAuthError, ProviderConfig } from '../../types.js';
import type {
  OIDCProviderConfig,
  OIDCProviderMetadata,
  OIDCErrorContext,
  PKCEPair,
  PKCEStorageHook,
} from './types.js';
import { validate as validateConfig } from './config.js';
import { createHash, randomBytes } from 'crypto';

/**
 * Internal mock storage hook for PKCE state persistence
 * Used as fallback when no storageHook is provided
 * Suitable for development and testing only
 */
class MockPKCEStorageHook implements PKCEStorageHook {
  private storage = new Map<
    string,
    { state: string; codeVerifier: string; expiresAt: number }
  >();

  async storePKCEState(
    interactionId: string,
    state: string,
    codeVerifier: string,
    expiresAt: number
  ): Promise<void> {
    this.storage.set(interactionId, { state, codeVerifier, expiresAt });
  }

  async retrievePKCEState(
    interactionId: string,
    state: string
  ): Promise<string | null> {
    const entry = this.storage.get(interactionId);
    if (!entry) return null;

    if (entry.state !== state) return null;
    if (Date.now() > entry.expiresAt) {
      this.storage.delete(interactionId);
      return null;
    }

    return entry.codeVerifier;
  }

  async cleanupExpiredState(beforeTimestamp: number): Promise<void> {
    for (const [key, entry] of this.storage.entries()) {
      if (entry.expiresAt < beforeTimestamp) {
        this.storage.delete(key);
      }
    }
  }
}

/**
 * OIDC Provider Adapter
 * Implements OIDC discovery, PKCE S256, and standardized OAuth flows
 */
export class OIDCProviderAdapter extends BaseOAuthAdapter {
  /** Provider name identifier */
  public readonly providerName = 'oidc-provider';

  /** OIDC-specific configuration */
  private readonly oidcConfig: OIDCProviderConfig;

  /** Cached OIDC provider metadata */
  private providerMetadata?: OIDCProviderMetadata;

  /** PKCE storage hook */
  private storageHook: PKCEStorageHook;

  /** PKCE state expiration time in seconds */
  private readonly pkceStateExpirationSeconds: number;

  // Note: initialized property is inherited from BaseOAuthAdapter

  /**
   * Creates a new OIDC Provider Adapter instance
   * @param config - OIDC provider configuration
   */
  public constructor(config: OIDCProviderConfig) {
    // Validate configuration using Zod schema
    const validatedConfig = validateConfig(config);

    // Convert to base ProviderConfig format for compatibility
    const baseConfig = {
      clientId: validatedConfig.clientId,
      clientSecret: validatedConfig.clientSecret,
      scopes: validatedConfig.scopes,
      customParameters: validatedConfig.additionalParameters as
        | Record<string, string>
        | undefined,
      redirectUri: validatedConfig.redirectUri,
    } as ProviderConfig;

    super(baseConfig);
    this.oidcConfig = validatedConfig as OIDCProviderConfig;
    this.storageHook = validatedConfig.storageHook || new MockPKCEStorageHook();
    this.pkceStateExpirationSeconds =
      validatedConfig.pkceStateExpirationSeconds || 600; // 10 minutes default
  }

  /**
   * Initialize the OIDC provider with discovery or static metadata
   * @throws {OAuthError} If initialization fails
   */
  public async initialize(): Promise<void> {
    try {
      this.logger.info('Starting OIDC provider initialization', {
        stage: 'initialize',
        hasIssuer: Boolean(this.oidcConfig.issuer),
        hasMetadata: Boolean(this.oidcConfig.serverMetadata),
      });

      // Configuration is already validated in constructor

      // Perform discovery or use static metadata
      if (this.oidcConfig.issuer) {
        await this.performDiscovery();
      } else if (this.oidcConfig.serverMetadata) {
        this.useStaticMetadata();
      } else {
        throw this.createError(
          'invalid_request',
          'Either issuer or metadata must be provided',
          {
            stage: 'initialize',
          }
        );
      }

      this.initialized = true;

      this.logger.info('OIDC provider initialization completed successfully', {
        stage: 'initialize',
        issuer: this.providerMetadata?.issuer,
        usedDiscovery: Boolean(this.oidcConfig.issuer),
        discoveryUrl: this.oidcConfig.issuer
          ? `${this.oidcConfig.issuer}/.well-known/openid-configuration`
          : undefined,
      });
    } catch (error) {
      this.logger.error('OIDC provider initialization failed', {
        stage: 'initialize',
        issuer: this.oidcConfig.issuer,
        discoveryUrl: this.oidcConfig.issuer
          ? `${this.oidcConfig.issuer}/.well-known/openid-configuration`
          : undefined,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Generate authorization URL with PKCE S256
   * @param interactionId - OAuth state parameter for CSRF protection
   * @param redirectUrl - Redirect URL for OAuth callback
   * @returns Authorization URL with PKCE parameters
   * @throws {OAuthError} If URL generation fails
   */
  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
    if (!this.initialized) {
      throw this.createError(
        'invalid_request',
        'Adapter must be initialized before generating auth URL',
        {
          stage: 'generateAuthUrl',
        }
      );
    }

    try {
      this.logger.info('Generating authorization URL', {
        stage: 'generateAuthUrl',
        state: interactionId,
        scopes: this.oidcConfig.scopes,
      });

      // Generate PKCE pair
      const pkcePair = this.generatePKCEPair();

      // Store PKCE state
      const expiresAt = Date.now() + this.pkceStateExpirationSeconds * 1000;
      await this.storageHook.storePKCEState(
        interactionId,
        interactionId,
        pkcePair.codeVerifier,
        expiresAt
      );

      // Build authorization URL
      const authEndpoint = this.providerMetadata!.authorization_endpoint;
      const params = {
        response_type: 'code',
        client_id: this.oidcConfig.clientId,
        redirect_uri: redirectUrl,
        scope: this.oidcConfig.scopes.join(' '),
        state: interactionId,
        code_challenge: pkcePair.codeChallenge,
        code_challenge_method: pkcePair.codeChallengeMethod,
        ...this.oidcConfig.additionalParameters,
      };

      const url = this.buildAuthorizeUrl(authEndpoint, params);

      this.logger.info('Authorization URL generated successfully', {
        stage: 'generateAuthUrl',
        state: interactionId,
        hasCodeChallenge: Boolean(pkcePair.codeChallenge),
        codeChallengeMethod: pkcePair.codeChallengeMethod,
      });

      return url;
    } catch (error) {
      this.logger.error('Failed to generate authorization URL', {
        stage: 'generateAuthUrl',
        issuer: this.providerMetadata?.issuer,
        endpoint: this.providerMetadata?.authorization_endpoint,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Get OIDC provider metadata
   * @returns Provider metadata
   */
  public getProviderMetadata(): OIDCProviderMetadata | undefined {
    return this.providerMetadata;
  }

  // === Protected Methods ===

  /**
   * Get authorization endpoint from provider metadata
   */
  protected getAuthorizationEndpoint(): string {
    if (!this.providerMetadata) {
      throw this.createError(
        'invalid_request',
        'Provider metadata not available',
        {
          stage: 'generateAuthUrl',
        }
      );
    }
    return this.providerMetadata.authorization_endpoint;
  }

  // === Private Methods ===

  /**
   * Perform OIDC discovery
   */
  private async performDiscovery(): Promise<void> {
    if (!this.oidcConfig.issuer) {
      throw this.createError(
        'invalid_request',
        'Issuer not provided for discovery',
        {
          stage: 'discovery',
        }
      );
    }

    const discoveryUrl = `${this.oidcConfig.issuer}/.well-known/openid-configuration`;

    try {
      this.logger.info('Performing OIDC discovery', {
        stage: 'discovery',
        discoveryUrl,
        issuer: this.oidcConfig.issuer,
      });

      // TODO: Implement actual OIDC discovery using openid-client
      // This is a placeholder implementation
      const response = await fetch(discoveryUrl);

      if (!response.ok) {
        throw this.createError(
          'server_error',
          `Discovery failed with status ${response.status}`,
          {
            stage: 'discovery',
            issuer: this.oidcConfig.issuer,
            discoveryUrl,
            endpoint: discoveryUrl,
          }
        );
      }

      const metadata = (await response.json()) as OIDCProviderMetadata;

      // Validate required endpoints
      this.validateProviderMetadata(metadata);

      this.providerMetadata = metadata;

      this.logger.info('OIDC discovery completed successfully', {
        stage: 'discovery',
        discoveryUrl,
        issuer: metadata.issuer,
        hasAuthorizationEndpoint: Boolean(metadata.authorization_endpoint),
        hasTokenEndpoint: Boolean(metadata.token_endpoint),
        hasUserinfoEndpoint: Boolean(metadata.userinfo_endpoint),
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('fetch')) {
        throw this.createError(
          'server_error',
          'Failed to perform OIDC discovery',
          {
            stage: 'discovery',
            issuer: this.oidcConfig.issuer,
            discoveryUrl,
            endpoint: discoveryUrl,
          }
        );
      }
      throw error;
    }
  }

  /**
   * Use static provider metadata
   */
  private useStaticMetadata(): void {
    if (!this.oidcConfig.serverMetadata) {
      throw this.createError(
        'invalid_request',
        'Static metadata not provided',
        {
          stage: 'initialize',
        }
      );
    }

    this.logger.info('Using static OIDC provider metadata', {
      stage: 'initialize',
      issuer: this.oidcConfig.serverMetadata.issuer,
      hasAuthorizationEndpoint: Boolean(
        this.oidcConfig.serverMetadata.authorization_endpoint
      ),
      hasTokenEndpoint: Boolean(this.oidcConfig.serverMetadata.token_endpoint),
    });

    this.validateProviderMetadata(this.oidcConfig.serverMetadata);
    this.providerMetadata = this.oidcConfig.serverMetadata;
  }

  /**
   * Validate provider metadata has required endpoints
   */
  private validateProviderMetadata(metadata: OIDCProviderMetadata): void {
    if (!metadata.authorization_endpoint) {
      throw this.createError(
        'invalid_request',
        'Missing authorization_endpoint in provider metadata',
        {
          stage: 'initialize',
          issuer: metadata.issuer,
        }
      );
    }

    if (!metadata.token_endpoint) {
      throw this.createError(
        'invalid_request',
        'Missing token_endpoint in provider metadata',
        {
          stage: 'initialize',
          issuer: metadata.issuer,
        }
      );
    }

    if (!metadata.jwks_uri) {
      throw this.createError(
        'invalid_request',
        'Missing jwks_uri in provider metadata',
        {
          stage: 'initialize',
          issuer: metadata.issuer,
        }
      );
    }
  }

  /**
   * Generate PKCE code verifier and challenge pair
   */
  private generatePKCEPair(): PKCEPair {
    const codeVerifier = this.generateCodeVerifier();
    return this.createPKCEPair(codeVerifier);
  }

  /**
   * Create PKCE pair from existing code verifier
   */
  private createPKCEPair(codeVerifier: string): PKCEPair {
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    };
  }

  /**
   * Generate PKCE code verifier
   */
  private generateCodeVerifier(): string {
    // Generate 32 random bytes and base64url encode
    const bytes = randomBytes(32);
    return bytes.toString('base64url');
  }

  /**
   * Generate PKCE code challenge from verifier
   */
  private generateCodeChallenge(codeVerifier: string): string {
    const hash = createHash('sha256');
    hash.update(codeVerifier);
    return hash.digest('base64url');
  }

  /**
   * Create standardized error
   */
  private createError(
    error: string,
    description: string,
    context: OIDCErrorContext
  ): OAuthError {
    const errorContext: { endpoint?: string; issuer?: string } = {};
    if (context.endpoint) errorContext.endpoint = context.endpoint;
    if (context.issuer) errorContext.issuer = context.issuer;

    return this.normalizeError(
      { error, error_description: description, statusCode: 400 },
      errorContext
    );
  }

  /**
   * Exchange authorization code for access token
   * @param code - Authorization code from callback
   * @param verifier - PKCE code verifier
   * @param redirectUrl - Redirect URL used in authorization
   * @returns Token response
   */
  public async exchangeCode(
    _code: string,
    _verifier: string,
    _redirectUrl: string
  ): Promise<import('../../types.js').TokenResponse> {
    // TODO: Implement OIDC token exchange
    throw new Error('exchangeCode not yet implemented');
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - Refresh token
   * @returns New token response
   */
  public async refreshToken(
    _refreshToken: string
  ): Promise<import('../../types.js').TokenResponse> {
    // TODO: Implement OIDC token refresh
    throw new Error('refreshToken not yet implemented');
  }

  /**
   * Compute provider-specific capabilities and requirements
   * @returns Provider quirks
   */
  protected computeProviderQuirks(): import('../../types.js').ProviderQuirks {
    // Analyze provider metadata for capabilities
    const supportsRefreshTokens =
      this.providerMetadata?.grant_types_supported?.includes('refresh_token') ??
      true; // Default to true for OIDC providers

    const customParameters = Object.keys(
      this.oidcConfig.additionalParameters || {}
    );

    return {
      supportsOIDCDiscovery: !!this.oidcConfig.issuer,
      requiresPKCE: true, // OIDC always requires PKCE for security
      supportsRefreshTokens,
      customParameters,
    };
  }
}
