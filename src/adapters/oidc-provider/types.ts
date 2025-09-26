/**
 * OIDC Provider Adapter specific types and interfaces
 */

import type { ProviderConfig } from '../../types.js';

/**
 * OIDC Provider Metadata from discovery or static configuration
 */
export interface OIDCProviderMetadata {
  /** OIDC issuer URL */
  issuer: string;
  /** Authorization endpoint URL */
  authorization_endpoint: string;
  /** Token endpoint URL */
  token_endpoint: string;
  /** Userinfo endpoint URL (optional) */
  userinfo_endpoint?: string;
  /** JWKS URI for token verification */
  jwks_uri: string;
  /** Supported response types */
  response_types_supported: string[];
  /** Supported grant types */
  grant_types_supported: string[];
  /** Supported scopes */
  scopes_supported?: string[];
  /** Supported subject types */
  subject_types_supported: string[];
  /** Supported ID token signing algorithms */
  id_token_signing_alg_values_supported: string[];
  /** Supported token endpoint authentication methods */
  token_endpoint_auth_methods_supported: string[];
  /** Supported code challenge methods */
  code_challenge_methods_supported?: string[];
  /** Supported response modes */
  response_modes_supported?: string[];
  /** Supported claims */
  claims_supported?: string[];
  /** Additional custom properties */
  [key: string]: unknown;
}

/**
 * Storage hook interface for persisting PKCE state
 */
export interface PKCEStorageHook {
  /**
   * Store PKCE state for a given interaction
   * @param interactionId - Unique interaction identifier
   * @param state - OAuth state parameter
   * @param codeVerifier - PKCE code verifier
   * @param expiresAt - Expiration timestamp
   */
  storePKCEState(
    interactionId: string,
    state: string,
    codeVerifier: string,
    expiresAt: number
  ): Promise<void>;

  /**
   * Retrieve PKCE state for verification
   * @param interactionId - Unique interaction identifier
   * @param state - OAuth state parameter to verify
   * @returns PKCE code verifier if found and valid
   */
  retrievePKCEState(
    interactionId: string,
    state: string
  ): Promise<string | null>;

  /**
   * Clean up expired PKCE state
   * @param beforeTimestamp - Clean up entries before this timestamp
   */
  cleanupExpiredState(beforeTimestamp: number): Promise<void>;
}

/**
 * OIDC Provider Adapter configuration extending base ProviderConfig
 */
export interface OIDCProviderConfig extends ProviderConfig {
  /** OIDC issuer URL for discovery (exactly one of issuer or serverMetadata must be provided) */
  issuer?: string;
  /** Static OIDC provider metadata (exactly one of issuer or serverMetadata must be provided) */
  serverMetadata?: OIDCProviderMetadata;
  /** Custom parameters to include in authorization requests */
  customParameters?: Record<string, string>;
  /** Timeout configuration */
  timeouts?: {
    connect?: number;
    response?: number;
  };
  /** PKCE storage hook for state persistence (optional - uses mock fallback if not provided) */
  storageHook?: PKCEStorageHook;
  /** PKCE state expiration time in seconds (default: 600 = 10 minutes) */
  pkceStateExpirationSeconds?: number;
}

/**
 * OIDC Provider Adapter initialization result
 */
export interface OIDCInitializationResult {
  /** Whether discovery was used */
  usedDiscovery: boolean;
  /** Discovery URL used (if applicable) */
  discoveryUrl?: string;
  /** Provider metadata used */
  metadata: OIDCProviderMetadata;
  /** Provider capabilities */
  capabilities: OIDCProviderCapabilities;
}

/**
 * OIDC Provider capabilities
 */
export interface OIDCProviderCapabilities {
  /** Supports OIDC discovery */
  supportsOIDCDiscovery: boolean;
  /** Requires PKCE for security */
  requiresPKCE: boolean;
  /** Supports refresh tokens */
  supportsRefreshTokens: boolean;
  /** Supports userinfo endpoint */
  supportsUserInfo: boolean;
  /** Supported code challenge methods */
  supportedCodeChallengeMethods: string[];
  /** Supported response types */
  supportedResponseTypes: string[];
  /** Supported grant types */
  supportedGrantTypes: string[];
}

/**
 * Authorization URL generation options
 */
export interface OIDCAuthUrlOptions {
  /** OAuth state parameter for CSRF protection */
  state: string;
  /** OAuth scopes (overrides config scopes if provided) */
  scopes?: string[];
  /** Additional query parameters */
  additionalParams?: Record<string, string>;
  /** PKCE code verifier (auto-generated if not provided) */
  codeVerifier?: string;
}

/**
 * Authorization URL generation result
 */
export interface OIDCAuthUrlResult {
  /** Complete authorization URL */
  url: string;
  /** PKCE code verifier (store securely for token exchange) */
  codeVerifier: string;
  /** State parameter used (for verification) */
  state: string;
  /** Code challenge used in URL */
  codeChallenge: string;
  /** Challenge method used */
  codeChallengeMethod: 'S256';
}

/**
 * Raw token response from OIDC provider before normalization
 * Represents the JSON response body from the token endpoint
 */
export interface RawTokenResponse {
  /** OAuth access token (required in all responses) */
  access_token: string;
  /** Token type (typically "Bearer") */
  token_type?: string;
  /** Token expiration time in seconds */
  expires_in?: number;
  /** OAuth refresh token (if supported and requested) */
  refresh_token?: string;
  /** OIDC ID token (if requested with openid scope) */
  id_token?: string;
  /** Granted scopes (may differ from requested) */
  scope?: string;
  /** Additional provider-specific fields */
  [key: string]: unknown;
}
