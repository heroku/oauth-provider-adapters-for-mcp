/**
 * MCP OAuth Provider Adapters Library
 * Main entry point for OAuth provider adapters
 */

export const version = '0.0.1';

// Export all adapters
export * from './adapters/index.js';

// Export base adapter and types
export { BaseOAuthAdapter } from './base-adapter.js';
export type {
  ProviderConfig,
  TokenResponse,
  OAuthError,
  ProviderQuirks,
} from './types.js';

// Export utilities
export { ErrorNormalizer } from './utils/error-normalizer.js';

// Export logging utilities
export type {
  Logger,
  LogLevel,
  LogMeta,
  LogTransport,
} from './logging/types.js';
export { DefaultLogger } from './logging/logger.js';

export default {
  version,
};
