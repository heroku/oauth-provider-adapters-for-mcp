/**
 * Environment variable helper for OIDCProviderAdapter
 * Maps legacy environment variables to OIDCProviderConfig
 */

import type { OIDCProviderConfig, FromEnvironmentOptions } from './types.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';

/**
 * Default scopes used if IDENTITY_SCOPE is not provided
 */
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

/**
 * Create an OIDCProviderAdapter from environment variables
 *
 * Maps legacy IDENTITY_* environment variables to OIDCProviderConfig:
 * - IDENTITY_CLIENT_ID -> clientId
 * - IDENTITY_CLIENT_SECRET -> clientSecret
 * - IDENTITY_SERVER_URL -> issuer (for OIDC discovery)
 * - IDENTITY_REDIRECT_URI -> redirectUri
 * - IDENTITY_SCOPE -> scopes (split by spaces and commas)
 *
 * @param options - Configuration options
 * @returns Configured OIDCProviderAdapter instance
 * @throws Error if required environment variables are missing
 */
export function fromEnvironment(
  options: FromEnvironmentOptions = {}
): OIDCProviderAdapter {
  const env = options.env || process.env;
  const defaultScopes = options.defaultScopes || DEFAULT_SCOPES;

  // Extract and validate required environment variables in a single pass
  const {
    IDENTITY_CLIENT_ID,
    IDENTITY_CLIENT_SECRET,
    IDENTITY_SERVER_URL,
    IDENTITY_REDIRECT_URI,
  } = env;

  const clientId = IDENTITY_CLIENT_ID || '';
  const clientSecret = IDENTITY_CLIENT_SECRET || '';
  const serverUrl = IDENTITY_SERVER_URL || '';
  const redirectUri = IDENTITY_REDIRECT_URI || '';

  // Parse scopes: split by spaces and commas, filter empty strings
  const scopesString = env.IDENTITY_SCOPE || '';
  const scopes = scopesString
    ? scopesString
        .split(/[, ]+/)
        .filter(Boolean)
        .map((s) => s.trim())
    : defaultScopes;

  // Ensure issuer URL is properly formatted
  // Remove trailing slash for consistency with OIDC discovery
  const issuer = serverUrl.replace(/\/$/, '');

  // Build configuration
  const config: OIDCProviderConfig = {
    clientId,
    clientSecret,
    issuer,
    redirectUri,
    scopes,
  };

  // Add optional properties only if defined
  if (options.customParameters) {
    config.customParameters = options.customParameters;
  }

  if (options.storageHook) {
    config.storageHook = options.storageHook;
  }

  if (options.logger) {
    config.logger = options.logger;
  }

  // Create and return adapter instance
  return new OIDCProviderAdapter(config);
}

/**
 * Async version that also initializes the adapter
 *
 * @param options - Configuration options
 * @returns Initialized OIDCProviderAdapter instance
 * @throws Error if required environment variables are missing or initialization fails
 */
export async function fromEnvironmentAsync(
  options: FromEnvironmentOptions = {}
): Promise<OIDCProviderAdapter> {
  const adapter = fromEnvironment(options);
  await adapter.initialize();
  return adapter;
}
