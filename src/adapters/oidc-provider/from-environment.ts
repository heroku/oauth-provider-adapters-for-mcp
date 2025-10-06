/**
 * Environment variable helper for OIDCProviderAdapter
 * Maps legacy environment variables to OIDCProviderConfig
 */

import type { OIDCProviderConfig, PKCEStorageHook } from './types.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';

/**
 * Environment variable names used by legacy OIDC configuration
 */
export interface LegacyEnvironmentVariables {
  /** OIDC Client ID */
  IDENTITY_CLIENT_ID?: string;
  /** OIDC Client Secret */
  IDENTITY_CLIENT_SECRET?: string;
  /** OIDC Server/Issuer URL */
  IDENTITY_SERVER_URL?: string;
  /** OAuth scopes (space or comma separated) */
  IDENTITY_SCOPE?: string;
  /** OAuth redirect URI */
  IDENTITY_REDIRECT_URI?: string;
  /** Allow any other environment variables */
  [key: string]: string | undefined;
}

/**
 * Options for creating OIDCProviderAdapter from environment
 */
export interface FromEnvironmentOptions {
  /** Optional PKCE storage hook implementation */
  storageHook?: PKCEStorageHook;
  /** Optional custom environment variables object (defaults to process.env) */
  env?: LegacyEnvironmentVariables;
  /** Default scopes if IDENTITY_SCOPE is not provided */
  defaultScopes?: string[];
  /** Additional custom parameters for authorization requests */
  customParameters?: Record<string, string>;
}

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

  // Validate required environment variables
  const clientId = env.IDENTITY_CLIENT_ID;
  const clientSecret = env.IDENTITY_CLIENT_SECRET;
  const serverUrl = env.IDENTITY_SERVER_URL;
  const redirectUri = env.IDENTITY_REDIRECT_URI;

  if (!clientId) {
    throw new Error(
      'Missing required environment variable: IDENTITY_CLIENT_ID'
    );
  }

  if (!clientSecret) {
    throw new Error(
      'Missing required environment variable: IDENTITY_CLIENT_SECRET'
    );
  }

  if (!serverUrl) {
    throw new Error(
      'Missing required environment variable: IDENTITY_SERVER_URL'
    );
  }

  if (!redirectUri) {
    throw new Error(
      'Missing required environment variable: IDENTITY_REDIRECT_URI'
    );
  }

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
