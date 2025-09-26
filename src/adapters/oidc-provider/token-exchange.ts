/**
 * Token exchange operations for OIDC Provider Adapter
 */

import type { TokenResponse, OAuthError } from '../../types.js';
import type {
  OIDCProviderConfig,
  OIDCProviderMetadata,
  RawTokenResponse,
} from './types.js';
import {
  normalizeScope,
  extractUserData,
  isNormalizedOAuthError,
} from './utils.js';

/**
 * Token exchange service for OIDC operations
 */
export class TokenExchangeService {
  constructor(
    private readonly config: OIDCProviderConfig,
    private readonly metadata: OIDCProviderMetadata,
    private readonly logger: any,
    private readonly createStandardError: (
      error: string,
      description: string,
      context?: any
    ) => OAuthError,
    private readonly normalizeError: (
      error: unknown,
      context?: any
    ) => OAuthError
  ) {}

  /**
   * Exchange authorization code for access token
   * @param code - Authorization code from callback
   * @param verifier - PKCE code verifier
   * @param redirectUrl - Redirect URL used in authorization
   * @returns Token response
   */
  async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    if (!this.metadata.token_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Token endpoint not available',
        {
          stage: 'exchangeCode',
          ...(this.metadata.issuer && {
            issuer: this.metadata.issuer,
          }),
        }
      );
    }

    try {
      this.logger.info('Exchanging authorization code for tokens', {
        stage: 'exchangeCode',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
      });

      // Build token request parameters
      const tokenParams = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        redirect_uri: redirectUrl,
        client_id: this.config.clientId,
      });

      // Add client_secret if provided (for confidential clients)
      if (this.config.clientSecret) {
        tokenParams.append('client_secret', this.config.clientSecret);
      }

      // Make token exchange request
      const response = await fetch(this.metadata.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: tokenParams.toString(),
      });

      const responseData = await this.parseTokenResponse(
        response,
        'exchangeCode'
      );

      // Handle OAuth error responses
      if (!response.ok) {
        throw this.createStandardError(
          responseData.error || 'server_error',
          responseData.error_description ||
            `Token exchange failed: ${response.status} ${response.statusText}`,
          {
            stage: 'exchangeCode',
            issuer: this.metadata.issuer,
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
            issuer: this.metadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      const tokenResponse = this.buildTokenResponse(responseData);

      this.logger.info('Authorization code exchange completed successfully', {
        stage: 'exchangeCode',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
        hasRefreshToken: Boolean(tokenResponse.refreshToken),
        hasIdToken: Boolean(tokenResponse.idToken),
        expiresIn: tokenResponse.expiresIn,
      });

      return tokenResponse;
    } catch (error) {
      this.logger.error('Authorization code exchange failed', {
        stage: 'exchangeCode',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
        error: error instanceof Error ? error.message : String(error),
      });

      // Re-throw if already normalized OAuthError
      if (isNormalizedOAuthError(error)) {
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
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    if (!this.metadata.token_endpoint) {
      throw this.createStandardError(
        'invalid_request',
        'Token endpoint not available',
        {
          stage: 'refreshToken',
          ...(this.metadata.issuer && {
            issuer: this.metadata.issuer,
          }),
        }
      );
    }

    try {
      this.logger.info('Refreshing access token', {
        stage: 'refreshToken',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
      });

      // Build token refresh request parameters
      const tokenParams = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
      });

      // Add client_secret if provided (for confidential clients)
      if (this.config.clientSecret) {
        tokenParams.append('client_secret', this.config.clientSecret);
      }

      // Make token refresh request
      const response = await fetch(this.metadata.token_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: tokenParams.toString(),
      });

      const responseData = await this.parseTokenResponse(
        response,
        'refreshToken'
      );

      // Handle OAuth error responses
      if (!response.ok) {
        throw this.createStandardError(
          responseData.error || 'server_error',
          responseData.error_description ||
            `Token refresh failed: ${response.status} ${response.statusText}`,
          {
            stage: 'refreshToken',
            issuer: this.metadata.issuer,
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
            issuer: this.metadata.issuer,
            endpoint: 'token_endpoint',
          }
        );
      }

      const tokenResponse = this.buildTokenResponse(responseData);

      this.logger.info('Token refresh completed successfully', {
        stage: 'refreshToken',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
        hasNewRefreshToken: Boolean(tokenResponse.refreshToken),
        hasIdToken: Boolean(tokenResponse.idToken),
        expiresIn: tokenResponse.expiresIn,
      });

      return tokenResponse;
    } catch (error) {
      this.logger.error('Token refresh failed', {
        stage: 'refreshToken',
        issuer: this.metadata.issuer,
        endpoint: this.metadata.token_endpoint,
        error: error instanceof Error ? error.message : String(error),
      });

      // Re-throw if already normalized OAuthError
      if (isNormalizedOAuthError(error)) {
        throw error;
      }

      throw this.normalizeError(error, {
        endpoint: 'token_endpoint',
      });
    }
  }

  /**
   * Parse JSON response from token endpoint with error handling
   */
  private async parseTokenResponse(
    response: Response,
    stage: string
  ): Promise<any> {
    try {
      return await response.json();
    } catch {
      throw this.createStandardError(
        'server_error',
        'Invalid JSON response from token endpoint',
        {
          stage,
          issuer: this.metadata.issuer,
          endpoint: 'token_endpoint',
        }
      );
    }
  }

  /**
   * Build normalized token response from provider data
   */
  private buildTokenResponse(responseData: RawTokenResponse): TokenResponse {
    // Normalize scope field
    const normalizedScope = normalizeScope(
      responseData.scope,
      this.config.scopes
    );

    // Extract additional provider fields for userData
    const userData = extractUserData(responseData);

    return {
      accessToken: responseData.access_token,
      ...(responseData.refresh_token && {
        refreshToken: responseData.refresh_token,
      }),
      ...(responseData.id_token && { idToken: responseData.id_token }),
      ...(responseData.expires_in && { expiresIn: responseData.expires_in }),
      scope: normalizedScope,
      ...(userData && { userData }),
    };
  }
}
