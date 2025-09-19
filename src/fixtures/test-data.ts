/**
 * Consolidated test fixtures
 * Simple, focused test data for all test files
 */

import type { ProviderConfig, TokenResponse } from '../types.js';

// ============================================================================
// COMMON TEST DATA
// ============================================================================

export const testConfigs = {
  valid: {
    clientId: 'test-client-id',
    scopes: ['openid', 'profile', 'email'],
    customParameters: { custom_param: 'custom_value' },
  } as ProviderConfig,

  minimal: {
    clientId: 'test-client-id',
    scopes: ['openid'],
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
    // Missing required authorization_endpoint
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
