/**
 * Test adapters for testing the BaseOAuthAdapter class
 */

import { BaseOAuthAdapter } from '../base-adapter.js';
import type {
  OAuthError,
  ProviderConfig,
  ProviderQuirks,
  TokenResponse,
} from '../types.js';

/**
 * Configuration options for test adapters
 */
export interface ConfigurableTestAdapterOptions {
  /** Authorization endpoint URL */
  authEndpoint?: string;
  /** Whether the adapter should be initialized */
  initialized?: boolean;
  /** Provider quirks to return */
  quirks?: Partial<ProviderQuirks>;
  /** Token response to return from exchangeCode */
  tokenResponse?: TokenResponse;
  /** Token response to return from refreshToken */
  refreshTokenResponse?: TokenResponse;
  /** Error to throw from exchangeCode */
  exchangeCodeError?: unknown;
  /** Error to throw from refreshToken */
  refreshTokenError?: unknown;
  /** Whether refresh tokens are supported */
  supportsRefresh?: boolean;
}

/**
 * Base test adapter that can be configured for different test scenarios
 */
export class ConfigurableTestAdapter extends BaseOAuthAdapter {
  private options: ConfigurableTestAdapterOptions;
  private _manuallyInitialized = false;

  constructor(
    config: ProviderConfig,
    options: ConfigurableTestAdapterOptions = {}
  ) {
    super(config);
    this.options = {
      authEndpoint: 'https://auth.example.com/authorize',
      initialized: true,
      quirks: {},
      tokenResponse: { accessToken: 'default-access-token' },
      refreshTokenResponse: { accessToken: 'default-refresh-token' },
      supportsRefresh: true,
      ...options,
    };
  }

  public async initialize(): Promise<void> {
    this._manuallyInitialized = true;
  }

  protected getAuthorizationEndpoint(): string {
    return this.options.authEndpoint!;
  }

  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
    return super.generateAuthUrl(interactionId, redirectUrl);
  }

  public async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    void code;
    void verifier;
    void redirectUrl;

    if (this.options.exchangeCodeError) {
      throw this.normalizeError(this.options.exchangeCodeError, {
        endpoint: '/token',
      });
    }

    return this.options.tokenResponse!;
  }

  public async refreshToken(refreshToken: string): Promise<TokenResponse> {
    void refreshToken;

    if (!this.options.supportsRefresh) {
      const unsupportedError: OAuthError = {
        statusCode: 400,
        error: 'unsupported_grant_type',
        error_description: 'Refresh token not supported',
      };
      throw this.normalizeError(unsupportedError, { endpoint: '/token' });
    }

    if (this.options.refreshTokenError) {
      throw this.normalizeError(this.options.refreshTokenError, {
        endpoint: '/token',
      });
    }

    return this.options.refreshTokenResponse!;
  }

  protected computeProviderQuirks(): ProviderQuirks {
    const defaultQuirks: ProviderQuirks = {
      supportsOIDCDiscovery: true,
      requiresPKCE: true,
      supportsRefreshTokens: this.options.supportsRefresh ?? true,
      customParameters: [],
    };

    return { ...defaultQuirks, ...this.options.quirks };
  }

  /**
   * Expose the config for testing
   */
  public getConfig(): ProviderConfig {
    return this.config;
  }

  /**
   * Expose normalizeError for testing
   */
  public exposeNormalizeError(
    e: unknown,
    context: { endpoint?: string; issuer?: string }
  ): OAuthError {
    return this.normalizeError(e, context);
  }
}

/**
 * Test adapter that simulates successful token exchange with provider response mapping
 */
export class TokenMappingTestAdapter extends BaseOAuthAdapter {
  public async initialize(): Promise<void> {
    return;
  }

  protected getAuthorizationEndpoint(): string {
    return 'https://auth.example.com/authorize';
  }

  public async generateAuthUrl(i: string, r: string): Promise<string> {
    return `${i}:${r}`;
  }

  public async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    void code;
    void verifier;
    void redirectUrl;

    // Simulate provider response mapping
    const providerResponse = {
      access_token: 'A',
      refresh_token: 'R',
      id_token: 'ID',
      expires_in: 3600,
      scope: 'openid profile',
    } as const;

    return {
      accessToken: providerResponse.access_token,
      refreshToken: providerResponse.refresh_token,
      idToken: providerResponse.id_token,
      expiresIn: providerResponse.expires_in,
      scope: providerResponse.scope,
    };
  }

  public async refreshToken(refreshToken: string): Promise<TokenResponse> {
    void refreshToken;
    return { accessToken: 'X' };
  }

  protected computeProviderQuirks(): ProviderQuirks {
    return {
      supportsOIDCDiscovery: true,
      requiresPKCE: true,
      supportsRefreshTokens: true,
      customParameters: [],
    };
  }
}

/**
 * Test adapter that throws provider-shaped errors for testing error normalization
 */
export class ErrorThrowingTestAdapter extends BaseOAuthAdapter {
  public async initialize(): Promise<void> {
    return;
  }

  protected getAuthorizationEndpoint(): string {
    return 'https://auth.example.com/authorize';
  }

  public async generateAuthUrl(i: string, r: string): Promise<string> {
    return `${i}:${r}`;
  }

  public async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    void code;
    void verifier;
    void redirectUrl;

    try {
      // Simulate provider throwing an HTTP-like error
      throw {
        response: {
          status: 400,
          data: { error: 'invalid_grant', error_description: 'bad code' },
        },
      };
    } catch (e) {
      throw this.normalizeError(e, { endpoint: '/token' });
    }
  }

  public async refreshToken(refreshToken: string): Promise<TokenResponse> {
    void refreshToken;
    return { accessToken: 'X' };
  }

  protected computeProviderQuirks(): ProviderQuirks {
    return {
      supportsOIDCDiscovery: true,
      requiresPKCE: true,
      supportsRefreshTokens: true,
      customParameters: [],
    };
  }

  public exposeNormalizeError(
    e: unknown,
    context: { endpoint?: string; issuer?: string }
  ): OAuthError {
    return this.normalizeError(e, context);
  }
}

/**
 * Test adapter for refresh token scenarios
 */
export class RefreshTokenTestAdapter extends BaseOAuthAdapter {
  private refreshSupported: boolean;

  constructor(config: ProviderConfig, refreshSupported = true) {
    super(config);
    this.refreshSupported = refreshSupported;
  }

  public async initialize(): Promise<void> {
    return;
  }

  protected getAuthorizationEndpoint(): string {
    return 'https://auth.example.com/authorize';
  }

  public async generateAuthUrl(i: string, r: string): Promise<string> {
    return `${i}:${r}`;
  }

  public async exchangeCode(
    code: string,
    verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    void code;
    void verifier;
    void redirectUrl;
    return { accessToken: 'X' };
  }

  public async refreshToken(refreshToken: string): Promise<TokenResponse> {
    void refreshToken;

    if (!this.refreshSupported) {
      const unsupportedError: OAuthError = {
        statusCode: 400,
        error: 'unsupported_grant_type',
        error_description: 'Refresh token not supported',
      };
      throw this.normalizeError(unsupportedError, { endpoint: '/token' });
    }

    const providerResponse = {
      access_token: 'NEW',
      refresh_token: 'NEW_R',
    } as const;

    return {
      accessToken: providerResponse.access_token,
      refreshToken: providerResponse.refresh_token,
    };
  }

  protected computeProviderQuirks(): ProviderQuirks {
    return {
      supportsOIDCDiscovery: true,
      requiresPKCE: true,
      supportsRefreshTokens: this.refreshSupported,
      customParameters: [],
    };
  }
}
