/**
 * Configuration interface for OAuth providers
 */
export type ProviderConfig = {
  /** OAuth client identifier */
  clientId: string;
  /** OAuth client secret (optional for public clients) */
  clientSecret?: string;
  /** OIDC issuer URL for discovery (exactly one of issuer or metadata must be provided) */
  issuer?: string;
  /** Manual provider metadata (exactly one of issuer or metadata must be provided) */
  metadata?: Record<string, unknown>;
  /** OAuth scopes to request */
  scopes: string[];
  /** Additional parameters to include in authorization requests */
  additionalParameters?: Record<string, string>;
  /** Default redirect URI (optional; can be provided per call if not set) */
  redirectUri?: string;
};

/**
 * Standardized token response from OAuth token exchange
 */
export type TokenResponse = {
  /** OAuth access token */
  accessToken: string;
  /** OAuth refresh token (if supported by provider) */
  refreshToken?: string;
  /** OpenID Connect ID token (if requested) */
  idToken?: string;
  /** Token expiration time in seconds */
  expiresIn?: number;
  /** Granted scopes (may differ from requested) */
  scope?: string;
  /** Additional user data from provider */
  userData?: Record<string, unknown>;
};

/**
 * Provider-specific capabilities and requirements
 */
export type ProviderQuirks = {
  /** Whether the provider supports OIDC discovery */
  supportsOIDCDiscovery: boolean;
  /** Whether the provider requires PKCE for authorization */
  requiresPKCE: boolean;
  /** Whether the provider supports refresh tokens */
  supportsRefreshTokens: boolean;
  /** List of additional parameter keys supported by the provider */
  additionalParameters: string[];
};
/**
 * Standardized OAuth error shape for consistent error handling
 */
export type OAuthError = {
  /** HTTP status code */
  statusCode: number;
  /** OAuth error code */
  error: string;
  /** Human-readable error description */
  error_description?: string;
  /** Endpoint that generated the error */
  endpoint?: string;
  /** Provider issuer identifier */
  issuer?: string;
};
