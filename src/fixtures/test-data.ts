/**
 * Consolidated test fixtures
 * Simple, focused test data for all test files
 */

import type { ProviderConfig, TokenResponse } from '../types.js';
import type { OIDCProviderConfig } from '../adapters/oidc-provider/types.js';

// ============================================================================
// COMMON TEST DATA
// ============================================================================

export const testConfigs = {
  valid: {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    scopes: ['openid', 'profile', 'email'],
    redirectUri: 'https://example.com/callback',
  } as ProviderConfig,
};

// ============================================================================
// ERROR TEST DATA
// ============================================================================

export const errorData = {
  http400: {
    status: 400,
    statusText: 'Bad Request',
    data: { error: 'invalid_request', error_description: 'Invalid client' },
  },

  http401: {
    status: 401,
    statusText: 'Unauthorized',
    data: { error: 'invalid_client', error_description: 'Invalid credentials' },
  },

  networkTimeout: new Error('Network timeout'),

  openidError: {
    error: 'invalid_grant',
    error_description: 'Invalid authorization code',
    statusCode: 400,
  },
};

export const contextData = {
  tokenEndpoint: { endpoint: '/token', issuer: 'https://auth.example.com' },
  discoveryEndpoint: { endpoint: '/discovery' },
  authorizeEndpoint: { endpoint: '/authorize' },
};

// ============================================================================
// TOKEN RESPONSE DATA
// ============================================================================

export const tokenData = {
  success: {
    accessToken: 'test-access-token',
    refreshToken: 'test-refresh-token',
    idToken: 'test-id-token',
    expiresIn: 3600,
    scope: 'openid profile email',
  } as TokenResponse,

  minimal: {
    accessToken: 'minimal-access-token',
  } as TokenResponse,
};

// ============================================================================
// OIDC METADATA DATA
// ============================================================================

export const oidcMetadata = {
  base: {
    issuer: 'https://auth.example.com',
    authorization_endpoint: 'https://auth.example.com/oauth/authorize',
    token_endpoint: 'https://auth.example.com/oauth/token',
    jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
  },

  minimal: {
    issuer: 'https://auth.example.com',
    authorization_endpoint: 'https://auth.example.com/oauth/authorize',
    token_endpoint: 'https://auth.example.com/oauth/token',
    jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: [
      'client_secret_post',
      'client_secret_basic',
    ],
  },

  malformed: {
    issuer: 'https://auth.example.com',
    // Missing required authorization_endpoint to trigger validation error
    token_endpoint: 'https://auth.example.com/token',
    jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
  },
};

export const authUrlData = {
  validParams: {
    interactionId: 'test-state',
    redirectUrl: 'https://example.com/callback',
  },
  expectedUrlParts: [
    'response_type=code',
    'client_id=test-client',
    'state=test-state',
    'code_challenge=',
    'code_challenge_method=S256',
  ],
};

// ============================================================================
// MODULE EXPORT DATA
// ============================================================================

export const moduleData = {
  expectedVersion: '0.0.1',
  expectedExports: [
    'version',
    'BaseOAuthAdapter',
    'OIDCProviderAdapter',
    'default',
  ],
  expectedTypes: {
    version: 'string',
    BaseOAuthAdapter: 'function',
    OIDCProviderAdapter: 'function',
    default: 'object',
  },
};

// ============================================================================
// CONFIG FACTORY FUNCTIONS
// ============================================================================

/**
 * Base OIDC config factory with sensible defaults
 */
export const createOIDCConfig = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig => ({
  clientId: 'test-client-id',
  issuer: 'https://accounts.google.com',
  scopes: ['openid', 'profile', 'email'],
  ...overrides,
});

/**
 * OIDC config with server metadata instead of issuer
 */
export const createOIDCConfigWithMetadata = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig => {
  const { issuer: _issuer, ...rest } = overrides;
  return {
    clientId: 'test-client-id',
    scopes: ['openid', 'profile', 'email'],
    metadata: oidcMetadata.minimal,
    ...rest,
  };
};

/**
 * OIDC config with client secret (confidential client)
 */
export const createOIDCConfigWithSecret = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig =>
  createOIDCConfig({
    clientSecret: 'test-client-secret',
    ...overrides,
  });

/**
 * OIDC config with timeout configuration
 */
export const createOIDCConfigWithTimeouts = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig =>
  createOIDCConfig({
    timeouts: { connect: 5000, response: 10000 },
    ...overrides,
  });

/**
 * OIDC config with custom parameters
 */
export const createOIDCConfigWithParams = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig =>
  createOIDCConfig({
    customParameters: { prompt: 'login', access_type: 'offline' },
    ...overrides,
  });

/**
 * OIDC config with minimal scopes
 */
export const createOIDCConfigMinimal = (
  overrides: Partial<OIDCProviderConfig> = {}
): OIDCProviderConfig =>
  createOIDCConfig({
    scopes: ['openid'],
    ...overrides,
  });

/**
 * Base Provider config factory
 */
export const createProviderConfig = (
  overrides: Partial<ProviderConfig> = {}
): ProviderConfig => ({
  clientId: 'test-client-id',
  scopes: ['openid', 'profile', 'email'],
  ...overrides,
});

/**
 * Provider config with custom parameters
 */
export const createProviderConfigWithParams = (
  overrides: Partial<ProviderConfig> = {}
): ProviderConfig =>
  createProviderConfig({
    customParameters: { audience: 'test-audience', prompt: 'login' },
    ...overrides,
  });

/**
 * Minimal provider config (only required fields)
 */
export const createProviderConfigMinimal = (
  overrides: Partial<ProviderConfig> = {}
): ProviderConfig => ({
  clientId: 'minimal-client',
  scopes: ['read'],
  ...overrides,
});

// ============================================================================
// INVALID CONFIG FACTORIES (for error testing)
// ============================================================================

/**
 * Creates invalid OIDC configs for testing validation errors
 */
export const createInvalidOIDCConfig = (
  type:
    | 'missing-client-id'
    | 'invalid-issuer'
    | 'both-issuer-metadata'
    | 'empty-client-id'
    | 'malformed-metadata'
    | 'invalid-timeout'
): Partial<OIDCProviderConfig> => {
  switch (type) {
    case 'missing-client-id':
      return { scopes: ['openid'] };
    case 'invalid-issuer':
      return {
        clientId: 'test-client-id',
        issuer: 'not-a-valid-url',
        scopes: ['openid'],
      };
    case 'both-issuer-metadata':
      return {
        clientId: 'test-client-id',
        issuer: 'https://accounts.google.com',
        metadata: oidcMetadata.minimal,
        scopes: ['openid'],
      };
    case 'empty-client-id':
      return {
        clientId: '',
        issuer: 'https://accounts.google.com',
        scopes: ['openid'],
      };
    case 'malformed-metadata':
      return {
        clientId: 'test-client-id',
        metadata: oidcMetadata.malformed as any,
        scopes: ['openid'],
      };
    case 'invalid-timeout':
      return {
        clientId: 'test-client-id',
        issuer: 'https://accounts.google.com',
        scopes: ['openid'],
        timeouts: { connect: -1000, response: 'invalid' as any },
      };
  }
};
