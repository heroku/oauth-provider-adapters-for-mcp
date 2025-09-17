/**
 * Shared test metadata utilities
 * Provides consistent metadata objects for all test files
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load the comprehensive metadata from JSON file
const fullMetadata = JSON.parse(
  readFileSync(join(__dirname, '..', 'fixtures', 'oidc-metadata.json'), 'utf8')
);

/**
 * Base metadata with all required fields
 */
export const baseMetadata = {
  issuer: 'https://auth.example.com',
  authorization_endpoint: 'https://auth.example.com/oauth/authorize',
  token_endpoint: 'https://auth.example.com/oauth/token',
  jwks_uri: 'https://auth.example.com/.well-known/jwks.json'
};

/**
 * Minimal metadata for basic tests
 */
export const minimalMetadata = {
  ...baseMetadata,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic']
};

/**
 * Full metadata with all optional fields
 */
export const fullTestMetadata = {
  ...fullMetadata
};

/**
 * Metadata with refresh token support
 */
export const refreshTokenMetadata = {
  ...baseMetadata,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  code_challenge_methods_supported: ['S256'],
  response_modes_supported: ['query']
};

/**
 * Metadata with userinfo endpoint
 */
export const userInfoMetadata = {
  ...refreshTokenMetadata,
  userinfo_endpoint: 'https://auth.example.com/oauth/userinfo',
  claims_supported: ['sub', 'name', 'email', 'profile']
};

/**
 * Malformed metadata (missing required fields)
 */
export const malformedMetadata = {
  issuer: 'https://auth.example.com',
  // Missing required authorization_endpoint
  token_endpoint: 'https://auth.example.com/token',
  jwks_uri: 'https://auth.example.com/.well-known/jwks.json'
};

/**
 * Metadata with different endpoints (for discovery tests)
 */
export const discoveryMetadata = {
  issuer: 'https://auth.example.com',
  authorization_endpoint: 'https://auth.example.com/oauth/authorize',
  token_endpoint: 'https://auth.example.com/oauth/token',
  userinfo_endpoint: 'https://auth.example.com/oauth/userinfo',
  jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  code_challenge_methods_supported: ['S256'],
  response_modes_supported: ['query'],
  claims_supported: ['sub', 'name', 'email', 'profile']
};
