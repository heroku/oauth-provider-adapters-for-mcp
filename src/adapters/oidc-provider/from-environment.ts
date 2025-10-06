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

  // Validate required environment variables via a centralized map to avoid duplication
  const requiredEnv: Record<string, string | undefined> = {
    IDENTITY_CLIENT_ID: env.IDENTITY_CLIENT_ID,
    IDENTITY_CLIENT_SECRET: env.IDENTITY_CLIENT_SECRET,
    IDENTITY_SERVER_URL: env.IDENTITY_SERVER_URL,
    IDENTITY_REDIRECT_URI: env.IDENTITY_REDIRECT_URI,
  };

  for (const [key, value] of Object.entries(requiredEnv)) {
    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }

  // Safe after validation
  const clientId = requiredEnv.IDENTITY_CLIENT_ID as string;
  const clientSecret = requiredEnv.IDENTITY_CLIENT_SECRET as string;
  const serverUrl = requiredEnv.IDENTITY_SERVER_URL as string;
  const redirectUri = requiredEnv.IDENTITY_REDIRECT_URI as string;

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
