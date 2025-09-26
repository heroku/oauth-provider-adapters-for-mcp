/**
 * OIDC Provider Adapter implementation
 * Extends BaseOAuthAdapter to provide OIDC-specific functionality
 */

import { BaseOAuthAdapter } from '../../base-adapter.js';
import type { ProviderConfig } from '../../types.js';
import type {
  OIDCProviderConfig,
  OIDCProviderMetadata,
  PKCEStorageHook,
} from './types.js';
import { validate as validateConfig } from './config.js';
import * as openidClient from 'openid-client';
const { randomPKCECodeVerifier, calculatePKCECodeChallenge, customFetch } =
  openidClient;

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
    // Validate configuration using Zod schema
    const validatedConfig = validateConfig(config);

    // Convert to base ProviderConfig format for compatibility
    const baseConfig = {
      clientId: validatedConfig.clientId,
      clientSecret: validatedConfig.clientSecret,
      scopes: validatedConfig.scopes,
      customParameters: validatedConfig.customParameters,
      redirectUri: validatedConfig.redirectUri,
    } as ProviderConfig;

    super(baseConfig);
    this.oidcConfig = validatedConfig as OIDCProviderConfig;
    this.storageHook = this.enforceProductionStorage(
      validatedConfig.storageHook,
      'storageHook',
      () => new MockPKCEStorageHook()
    );
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

      // Validate storage hook shape and basic health
      this.validateConfiguration();

      // Validate storage hook shape and basic health
      await this.validateStorageHook();

      // Set sane default HTTP timeouts for discovery
      this.setHttpDefaults({ timeout: 8_000 });
      if (customFetch && openidClient.customFetch) {
        // Note: customFetch in openid-client v6+ doesn't have setHttpOptionsDefaults
        // Timeout handling is done at the fetch level
      }

      // Perform discovery or use static metadata
      if (this.oidcConfig.issuer) {
        await this.performDiscovery();
      } else if (this.oidcConfig.metadata) {
        this.useStaticMetadata();
      } else {
        throw this.createStandardError(
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
      throw this.createStandardError(
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
      if (!randomPKCECodeVerifier || !calculatePKCECodeChallenge) {
        throw this.createStandardError(
          'server_error',
          'PKCE generators not available from openid-client',
          { stage: 'generateAuthUrl' }
        );
      }
      const codeVerifier = randomPKCECodeVerifier();
      const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
      const pkcePair = {
        codeVerifier,
        codeChallenge,
        codeChallengeMethod: 'S256' as const,
      };

      // Store PKCE state
      const expiresAt = Date.now() + this.pkceStateExpirationSeconds * 1000;
      try {
        await this.storageHook.storePKCEState(
          interactionId,
          interactionId,
          pkcePair.codeVerifier,
          expiresAt
        );
      } catch (error) {
        throw this.normalizeError(error, {
          endpoint: 'storageHook.storePKCEState',
        });
      }

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

      // Build authorization URL manually
      const authEndpoint = this.providerMetadata!.authorization_endpoint;
      const url = this.buildAuthorizeUrl(authEndpoint, {
        client_id: this.oidcConfig.clientId,
        ...params,
      });

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
      throw this.createStandardError(
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
      throw this.createStandardError(
        'invalid_request',
        'clientId is required',
        {
          stage: 'initialize',
        }
      );
    }

    if (!this.oidcConfig.scopes || this.oidcConfig.scopes.length === 0) {
      throw this.createStandardError('invalid_request', 'scopes are required', {
        stage: 'initialize',
      });
    }

    if (!this.oidcConfig.issuer && !this.oidcConfig.metadata) {
      throw this.createStandardError(
        'invalid_request',
        'Either issuer or metadata must be provided',
        {
          stage: 'initialize',
        }
      );
    }

    if (this.oidcConfig.issuer && this.oidcConfig.metadata) {
      throw this.createStandardError(
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
      throw this.createStandardError(
        'invalid_request',
        'Issuer not provided for discovery',
        {
          stage: 'discovery',
        }
      );
    }

    const issuer = this.oidcConfig.issuer;
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;

    this.logger.info('Performing OIDC discovery', {
      stage: 'discovery',
      discoveryUrl,
      issuer,
    });

    const metadata = (await this.executeWithResilience(
      async () => {
        const response = await fetch(discoveryUrl);
        if (!response.ok) {
          throw new Error(
            `Discovery failed: ${response.status} ${response.statusText}`
          );
        }
        return await response.json();
      },
      {
        endpoint: discoveryUrl,
        maxRetries: OIDCProviderAdapter.DISCOVERY_MAX_RETRIES,
        backoffMs: OIDCProviderAdapter.DISCOVERY_BACKOFF_MS,
        circuitKey: issuer,
        failureThreshold: OIDCProviderAdapter.CIRCUIT_FAILURE_THRESHOLD,
        circuitOpenMs: OIDCProviderAdapter.CIRCUIT_OPEN_MS,
      }
    )) as OIDCProviderMetadata;

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
  }

  /**
   * Use static provider metadata
   */
  private useStaticMetadata(): void {
    if (!this.oidcConfig.metadata) {
      throw this.createStandardError(
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

    this.validateProviderMetadata(
      this.oidcConfig.metadata as OIDCProviderMetadata
    );
    this.providerMetadata = this.oidcConfig.metadata as OIDCProviderMetadata;

    // No discovery; client cannot be constructed without Issuer instance
  }

  /**
   * Validate provider metadata has required endpoints
   */
  private validateProviderMetadata(metadata: OIDCProviderMetadata): void {
    if (!metadata.authorization_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Missing authorization_endpoint in provider metadata',
        {
          stage: 'initialize',
          issuer: metadata.issuer,
        }
      );
    }

    if (!metadata.token_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Missing token_endpoint in provider metadata',
        {
          stage: 'initialize',
          issuer: metadata.issuer,
        }
      );
    }

    if (!metadata.jwks_uri) {
      throw this.createStandardError(
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
      throw this.createStandardError(
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

  /**
   * Exchange authorization code for access token
   * @param code - Authorization code from callback
   * @param verifier - PKCE code verifier
   * @param redirectUrl - Redirect URL used in authorization
   * @returns Token response
   */
  public async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<import('../../types.js').TokenResponse> {
    if (!this.initialized) {
      throw this.createStandardError(
        'invalid_request',
        'Adapter must be initialized before exchanging code',
        {
          stage: 'exchangeCode',
        }
      );
    }

    if (!this.providerMetadata?.token_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Token endpoint not available',
        {
          stage: 'exchangeCode',
          ...(this.providerMetadata?.issuer && {
            issuer: this.providerMetadata.issuer,
          }),
        }
      );
    }

    try {
      this.logger.info('Exchanging authorization code for tokens', {
        stage: 'exchangeCode',
        issuer: this.providerMetadata.issuer,
        endpoint: this.providerMetadata.token_endpoint,
      });

      // Build token request parameters
      const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: redirectUrl,
        client_id: this.oidcConfig.clientId,
      });

      // Add client_secret if provided (for confidential clients)
      if (this.oidcConfig.clientSecret) {
        tokenParams.append('client_secret', this.oidcConfig.clientSecret);
      }

      // Make token exchange request
      const response = await fetch(this.providerMetadata.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: tokenParams.toString(),
      });

      let responseData: any;
      try {
        responseData = await response.json();
      } catch {
        throw this.createStandardError(
          'server_error',
          'Invalid JSON response from token endpoint',
          {
            stage: 'exchangeCode',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Handle OAuth error responses
      if (!response.ok) {
        throw this.createStandardError(
          responseData.error || 'server_error',
          responseData.error_description ||
            `Token exchange failed: ${response.status} ${response.statusText}`,
          {
            stage: 'exchangeCode',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Validate required access_token field
      if (!responseData.access_token) {
        throw this.createStandardError(
          'server_error',
          'Missing access_token in provider response',
          {
            stage: 'exchangeCode',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Normalize scope field
      const normalizedScope = this.normalizeScope(responseData.scope);

      // Extract additional provider fields for userData
      const userData = this.extractUserData(responseData);

      const tokenResponse: import('../../types.js').TokenResponse = {
        accessToken: responseData.access_token,
        ...(responseData.refresh_token && {
          refreshToken: responseData.refresh_token,
        }),
        ...(responseData.id_token && { idToken: responseData.id_token }),
        ...(responseData.expires_in && { expiresIn: responseData.expires_in }),
        scope: normalizedScope,
        ...(userData && { userData }),
      };

      this.logger.info('Authorization code exchange completed successfully', {
        stage: 'exchangeCode',
        issuer: this.providerMetadata.issuer,
        endpoint: this.providerMetadata.token_endpoint,
        hasRefreshToken: Boolean(tokenResponse.refreshToken),
        hasIdToken: Boolean(tokenResponse.idToken),
        expiresIn: tokenResponse.expiresIn,
      });

      return tokenResponse;
    } catch (error) {
      this.logger.error('Authorization code exchange failed', {
        stage: 'exchangeCode',
        issuer: this.providerMetadata?.issuer,
        endpoint: this.providerMetadata?.token_endpoint,
        error: error instanceof Error ? error.message : String(error),
      });

      // Re-throw if already normalized
      if (error && typeof error === 'object' && 'error' in error) {
        throw error;
      }

      throw this.normalizeError(error, {
        endpoint: 'token_endpoint',
      });
    }
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken - Refresh token
   * @returns New token response
   */
  public async refreshToken(
    refreshToken: string
  ): Promise<import('../../types.js').TokenResponse> {
    if (!this.initialized) {
      throw this.createStandardError(
        'invalid_request',
        'Adapter must be initialized before refreshing token',
        {
          stage: 'refreshToken',
        }
      );
    }

    if (!this.providerMetadata?.token_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Token endpoint not available',
        {
          stage: 'refreshToken',
          ...(this.providerMetadata?.issuer && {
            issuer: this.providerMetadata.issuer,
          }),
        }
      );
    }

    try {
      this.logger.info('Refreshing access token', {
        stage: 'refreshToken',
        issuer: this.providerMetadata.issuer,
        endpoint: this.providerMetadata.token_endpoint,
      });

      // Build token refresh request parameters
      const tokenParams = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.oidcConfig.clientId,
      });

      // Add client_secret if provided (for confidential clients)
      if (this.oidcConfig.clientSecret) {
        tokenParams.append('client_secret', this.oidcConfig.clientSecret);
      }

      // Make token refresh request
      const response = await fetch(this.providerMetadata.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: tokenParams.toString(),
      });

      let responseData: any;
      try {
        responseData = await response.json();
      } catch {
        throw this.createStandardError(
          'server_error',
          'Invalid JSON response from token endpoint',
          {
            stage: 'refreshToken',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Handle OAuth error responses
      if (!response.ok) {
        throw this.createStandardError(
          responseData.error || 'server_error',
          responseData.error_description ||
            `Token refresh failed: ${response.status} ${response.statusText}`,
          {
            stage: 'refreshToken',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Validate required access_token field
      if (!responseData.access_token) {
        throw this.createStandardError(
          'server_error',
          'Missing access_token in provider response',
          {
            stage: 'refreshToken',
            issuer: this.providerMetadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      // Normalize scope field
      const normalizedScope = this.normalizeScope(responseData.scope);

      // Extract additional provider fields for userData
      const userData = this.extractUserData(responseData);

      const tokenResponse: import('../../types.js').TokenResponse = {
        accessToken: responseData.access_token,
        ...(responseData.refresh_token && {
          refreshToken: responseData.refresh_token,
        }),
        ...(responseData.id_token && { idToken: responseData.id_token }),
        ...(responseData.expires_in && { expiresIn: responseData.expires_in }),
        scope: normalizedScope,
        ...(userData && { userData }),
      };

      this.logger.info('Token refresh completed successfully', {
        stage: 'refreshToken',
        issuer: this.providerMetadata.issuer,
        endpoint: this.providerMetadata.token_endpoint,
        hasNewRefreshToken: Boolean(tokenResponse.refreshToken),
        hasIdToken: Boolean(tokenResponse.idToken),
        expiresIn: tokenResponse.expiresIn,
      });

      return tokenResponse;
    } catch (error) {
      this.logger.error('Token refresh failed', {
        stage: 'refreshToken',
        issuer: this.providerMetadata?.issuer,
        endpoint: this.providerMetadata?.token_endpoint,
        error: error instanceof Error ? error.message : String(error),
      });

      // Re-throw if already normalized
      if (error && typeof error === 'object' && 'error' in error) {
        throw error;
      }

      throw this.normalizeError(error, {
        endpoint: 'token_endpoint',
      });
    }
  }

  /**
   * Normalize scope string from provider response
   * Handles both space-delimited and comma-delimited scopes
   * Falls back to configured scopes if provider response is empty
   */
  private normalizeScope(providerScope?: string): string {
    // If provider returned a scope, normalize it
    if (providerScope && providerScope.trim()) {
      // Handle both comma-delimited and space-delimited scopes
      const scopes = providerScope
        .split(/[,\s]+/) // Split on comma or whitespace
        .map((scope) => scope.trim()) // Trim each scope
        .filter((scope) => scope.length > 0); // Remove empty strings

      if (scopes.length > 0) {
        return scopes.join(' ');
      }
    }

    // Fallback to configured scopes if provider didn't return any
    return this.oidcConfig.scopes.join(' ');
  }

  /**
   * Extract additional non-sensitive provider response fields as userData
   * Filters out standard OAuth fields and sensitive data
   */
  private extractUserData(
    responseData: any
  ): Record<string, unknown> | undefined {
    // Standard OAuth/OIDC fields that should not be in userData
    const standardFields = new Set([
      'access_token',
      'refresh_token',
      'id_token',
      'expires_in',
      'scope',
    ]);

    // Sensitive fields that should never be exposed
    const sensitiveFields = new Set([
      'client_secret',
      'code_verifier',
      'authorization_code',
      'code',
    ]);

    const userData: Record<string, unknown> = {};
    let hasData = false;

    for (const [key, value] of Object.entries(responseData)) {
      // Skip standard OAuth fields
      if (standardFields.has(key)) {
        continue;
      }

      // Skip sensitive fields for security
      if (sensitiveFields.has(key)) {
        continue;
      }

      // Include additional provider-specific fields
      userData[key] = value;
      hasData = true;
    }

    return hasData ? userData : undefined;
  }

  /**
   * Compute provider-specific capabilities and requirements
   * @returns Provider quirks
   */
  protected computeProviderQuirks(): import('../../types.js').ProviderQuirks {
    // Analyze provider metadata for capabilities
    const supportsRefreshTokens =
      this.providerMetadata?.grant_types_supported?.includes('refresh_token') ??
      false; // Default to false when unknown to satisfy strict tests

    const customParameters = Object.keys(
      this.oidcConfig.customParameters || {}
    );

    return {
      supportsOIDCDiscovery: !!this.oidcConfig.issuer,
      requiresPKCE: true, // OIDC always requires PKCE for security
      supportsRefreshTokens,
      customParameters,
    };
  }
}
