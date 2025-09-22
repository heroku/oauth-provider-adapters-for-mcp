/**
 * OIDC Provider Adapter implementation
 * Extends BaseOAuthAdapter to provide OIDC-specific functionality
 */

import { BaseOAuthAdapter } from '../../base-adapter.js';
import type { OAuthError } from '../../types.js';
import type {
  OIDCProviderConfig,
  OIDCProviderMetadata,
  OIDCErrorContext,
  PKCEPair,
  PKCEStorageHook,
} from './types.js';
import { Issuer, generators, custom, Client } from 'openid-client';

/**
 * Circuit breaker state type for discovery
 */
type DiscoveryCircuitState = {
  consecutiveFailures: number;
  openedUntil?: number;
};

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

  /** Discovered OpenID Issuer instance */
  private discoveredIssuer?: Issuer;

  /** OpenID Client built from discovered/static metadata */
  private oidcClient?: Client;

  /**
   * Simple circuit breaker state per issuer to avoid hammering failing discovery endpoints
   */
  private static discoveryCircuit: Map<string, DiscoveryCircuitState> =
    new Map();

  private static readonly DISCOVERY_MAX_RETRIES = 2; // total attempts = 1 + retries
  private static readonly DISCOVERY_BACKOFF_MS = 300; // base backoff
  private static readonly CIRCUIT_FAILURE_THRESHOLD = 3;
  private static readonly CIRCUIT_OPEN_MS = 60_000; // 60s

  // Note: initialized property is inherited from BaseOAuthAdapter

  /**
   * Creates a new OIDC Provider Adapter instance
   * @param config - OIDC provider configuration
   */
  public constructor(config: OIDCProviderConfig) {
    super(config);
    this.oidcConfig = config;
    if (!config.storageHook) {
      // Prevent unsafe fallback in production
      if (process.env.NODE_ENV === 'production') {
        throw this.createError(
          'invalid_request',
          'Persistent storageHook is required in production; in-memory storage is not allowed',
          { stage: 'initialize' }
        );
      }
      this.logger.warn(
        'No storageHook provided; using in-memory mock storage (not for production)',
        { stage: 'initialize' }
      );
      this.storageHook = new MockPKCEStorageHook();
    } else {
      this.storageHook = config.storageHook;
    }
    this.pkceStateExpirationSeconds = config.pkceStateExpirationSeconds || 600; // 10 minutes default
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
        hasMetadata: Boolean(this.oidcConfig.metadata),
      });

      // Validate configuration
      this.validateConfiguration();

      // Validate storage hook shape and basic health
      await this.validateStorageHook();

      // Set sane default HTTP timeouts for discovery
      custom.setHttpOptionsDefaults({ timeout: 8_000 });

      // Perform discovery or use static metadata
      if (this.oidcConfig.issuer) {
        await this.performDiscovery();
      } else if (this.oidcConfig.metadata) {
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

      // Generate PKCE pair using openid-client
      const codeVerifier = generators.codeVerifier();
      const codeChallenge = generators.codeChallenge(codeVerifier);
      const pkcePair = {
        codeVerifier,
        codeChallenge,
        codeChallengeMethod: 'S256' as const,
      };

      // Store PKCE state
      const expiresAt = Date.now() + this.pkceStateExpirationSeconds * 1000;
      await this.storageHook.storePKCEState(
        interactionId,
        interactionId,
        pkcePair.codeVerifier,
        expiresAt
      );

      // Build authorization URL via openid-client Client when available
      const params = {
        response_type: 'code',
        scope: this.oidcConfig.scopes.join(' '),
        state: interactionId,
        code_challenge: pkcePair.codeChallenge,
        code_challenge_method: pkcePair.codeChallengeMethod,
        redirect_uri: redirectUrl,
        ...this.oidcConfig.customParameters,
      } as Record<string, string>;

      let url: string;
      if (this.oidcClient) {
        url = this.oidcClient.authorizationUrl(params);
      } else {
        // Fallback to manual URL construction if client not available (static metadata path)
        const authEndpoint = this.providerMetadata!.authorization_endpoint;
        url = this.buildAuthorizeUrl(authEndpoint, {
          client_id: this.oidcConfig.clientId,
          ...params,
        });
      }

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
   * Validate OIDC provider configuration
   */
  private validateConfiguration(): void {
    if (!this.oidcConfig.clientId) {
      throw this.createError('invalid_request', 'clientId is required', {
        stage: 'initialize',
      });
    }

    if (!this.oidcConfig.scopes || this.oidcConfig.scopes.length === 0) {
      throw this.createError('invalid_request', 'scopes are required', {
        stage: 'initialize',
      });
    }

    if (!this.oidcConfig.issuer && !this.oidcConfig.metadata) {
      throw this.createError(
        'invalid_request',
        'Either issuer or metadata must be provided',
        {
          stage: 'initialize',
        }
      );
    }

    if (this.oidcConfig.issuer && this.oidcConfig.metadata) {
      throw this.createError(
        'invalid_request',
        'Cannot specify both issuer and metadata',
        {
          stage: 'initialize',
        }
      );
    }
  }

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

    const issuer = this.oidcConfig.issuer;
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;

    // Circuit breaker: if open, fail fast
    const circuit =
      OIDCProviderAdapter.discoveryCircuit.get(issuer) ||
      ({ consecutiveFailures: 0 } as DiscoveryCircuitState);
    if (circuit.openedUntil && Date.now() < circuit.openedUntil) {
      throw this.createError(
        'temporarily_unavailable',
        'Discovery circuit is open due to recent failures. Try again later.',
        { stage: 'discovery', issuer, discoveryUrl, endpoint: discoveryUrl }
      );
    }

    this.logger.info('Performing OIDC discovery', {
      stage: 'discovery',
      discoveryUrl,
      issuer,
    });

    let lastError: unknown;
    for (
      let attempt = 0;
      attempt <= OIDCProviderAdapter.DISCOVERY_MAX_RETRIES;
      attempt++
    ) {
      try {
        const discovered = await Issuer.discover(issuer);
        this.discoveredIssuer = discovered;
        const metadata = discovered.metadata as unknown as OIDCProviderMetadata;

        // Validate required endpoints
        this.validateProviderMetadata(metadata);

        this.providerMetadata = metadata;

        // Build a minimal client for authorization URL construction
        this.oidcClient = new discovered.Client({
          client_id: this.oidcConfig.clientId,
        });

        // Reset circuit breaker on success
        OIDCProviderAdapter.discoveryCircuit.set(issuer, {
          consecutiveFailures: 0,
        });

        this.logger.info('OIDC discovery completed successfully', {
          stage: 'discovery',
          discoveryUrl,
          issuer: metadata.issuer,
          hasAuthorizationEndpoint: Boolean(metadata.authorization_endpoint),
          hasTokenEndpoint: Boolean(metadata.token_endpoint),
          hasUserinfoEndpoint: Boolean(metadata.userinfo_endpoint),
        });
        return;
      } catch (e) {
        lastError = e;
        // Exponential backoff before retry, except after last attempt
        if (attempt < OIDCProviderAdapter.DISCOVERY_MAX_RETRIES) {
          const wait =
            OIDCProviderAdapter.DISCOVERY_BACKOFF_MS * Math.pow(2, attempt);
          await new Promise((res) => setTimeout(res, wait));
          continue;
        }
      }
    }

    // Update circuit breaker on failure exhaustion
    const failures = (circuit.consecutiveFailures || 0) + 1;
    const shouldOpen =
      failures >= OIDCProviderAdapter.CIRCUIT_FAILURE_THRESHOLD;
    const newState: DiscoveryCircuitState = { consecutiveFailures: failures };
    if (shouldOpen) {
      newState.openedUntil = Date.now() + OIDCProviderAdapter.CIRCUIT_OPEN_MS;
    }
    OIDCProviderAdapter.discoveryCircuit.set(issuer, newState);

    throw this.normalizeError(lastError, {
      issuer,
      endpoint: discoveryUrl,
    });
  }

  /**
   * Use static provider metadata
   */
  private useStaticMetadata(): void {
    if (!this.oidcConfig.metadata) {
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
      issuer: this.oidcConfig.metadata.issuer,
      hasAuthorizationEndpoint: Boolean(
        this.oidcConfig.metadata.authorization_endpoint
      ),
      hasTokenEndpoint: Boolean(this.oidcConfig.metadata.token_endpoint),
    });

    this.validateProviderMetadata(this.oidcConfig.metadata);
    this.providerMetadata = this.oidcConfig.metadata;

    // No discovery; client cannot be constructed without Issuer instance
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
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    };
  }

  /**
   * Create PKCE pair from existing code verifier
   */
  private createPKCEPair(codeVerifier: string): PKCEPair {
    const codeChallenge = generators.codeChallenge(codeVerifier);
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
    return generators.codeVerifier();
  }

  /**
   * Generate PKCE code challenge from verifier
   */
  private generateCodeChallenge(codeVerifier: string): string {
    return generators.codeChallenge(codeVerifier);
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
   * Validate storage hook contract and perform lightweight health check
   */
  private async validateStorageHook(): Promise<void> {
    const hook = this.storageHook;
    const hasMethods =
      hook &&
      typeof hook.storePKCEState === 'function' &&
      typeof hook.retrievePKCEState === 'function' &&
      typeof hook.cleanupExpiredState === 'function';
    if (!hasMethods) {
      throw this.createError(
        'invalid_request',
        'storageHook must implement storePKCEState, retrievePKCEState, and cleanupExpiredState',
        { stage: 'initialize' }
      );
    }

    // Lightweight health check: ensure cleanupExpiredState resolves
    try {
      await hook.cleanupExpiredState(Date.now());
    } catch (e) {
      throw this.normalizeError(e, {
        endpoint: 'storageHook.cleanupExpiredState',
      });
    }
  }

  // End class members above

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
    return {
      supportsOIDCDiscovery: !!this.oidcConfig.issuer,
      requiresPKCE: true,
      supportsRefreshTokens:
        this.providerMetadata?.grant_types_supported?.includes(
          'refresh_token'
        ) ?? false,
      customParameters: Object.keys(this.oidcConfig.customParameters || {}),
    };
  }
}
