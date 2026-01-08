/**
 * Shared utilities for OIDC Provider Adapter
 */

import type { OIDCProviderMetadata, RawTokenResponse } from './types.js';
import type { OAuthError } from '../../types.js';

/**
 * Constants for OIDC discovery and resilience
 */
export const OIDC_CONSTANTS = {
  DISCOVERY_MAX_RETRIES: 2, // total attempts = 1 + retries
  DISCOVERY_BACKOFF_MS: 300, // base backoff
  CIRCUIT_FAILURE_THRESHOLD: 3,
  CIRCUIT_OPEN_MS: 60_000, // 60s
} as const;

/**
 * Standard OAuth/OIDC fields that should not be in userData
 */
export const STANDARD_TOKEN_FIELDS = new Set([
  'access_token',
  'refresh_token',
  'id_token',
  'expires_in',
  'scope',
]);

/**
 * Sensitive fields that should never be exposed in userData
 */
export const SENSITIVE_FIELDS = new Set([
  'client_secret',
  'code_verifier',
  'authorization_code',
  'code',
]);

/**
 * Normalize scope string from provider response
 * Handles both space-delimited and comma-delimited scopes
 * Falls back to configured scopes if provider response is empty
 */
export function normalizeScope(
  providerScope: string | undefined,
  configuredScopes: string[]
): string {
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
  return configuredScopes.join(' ');
}

/**
 * Extract additional non-sensitive provider response fields as userData
 * Filters out standard OAuth fields and sensitive data
 */
export function extractUserData(
  responseData: RawTokenResponse
): Record<string, unknown> | undefined {
  const userData: Record<string, unknown> = {};
  let hasData = false;

  for (const [key, value] of Object.entries(responseData)) {
    // Skip standard OAuth fields
    if (STANDARD_TOKEN_FIELDS.has(key)) {
      continue;
    }

    // Skip sensitive fields for security
    if (SENSITIVE_FIELDS.has(key)) {
      continue;
    }

    // Include additional provider-specific fields
    userData[key] = value;
    hasData = true;
  }

  return hasData ? userData : undefined;
}

/**
 * Validate provider metadata has required endpoints
 */
export function validateProviderMetadata(metadata: OIDCProviderMetadata): void {
  if (!metadata.authorization_endpoint) {
    throw new Error('Missing authorization_endpoint in provider metadata');
  }

  if (!metadata.token_endpoint) {
    throw new Error('Missing token_endpoint in provider metadata');
  }

  // Note: jwks_uri is optional - not all OIDC providers expose a JWKS endpoint
  // (e.g., Heroku Identity uses a different mechanism for token verification)
}

/**
 * Type guard to check if an error is already a normalized OAuthError
 * Uses the same logic as ErrorNormalizer.tryOAuthErrorShape() to detect
 * objects that have both 'error' and 'statusCode' properties
 */
export function isNormalizedOAuthError(error: unknown): error is OAuthError {
  return (
    error !== null &&
    typeof error === 'object' &&
    'error' in error &&
    typeof (error as any).error === 'string' &&
    ('statusCode' in error || 'status' in error) &&
    typeof ((error as any).statusCode ?? (error as any).status) === 'number'
  );
}
