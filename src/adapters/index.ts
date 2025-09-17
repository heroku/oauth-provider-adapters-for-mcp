/**
 * OAuth Provider Adapters exports
 */

// OIDC Provider Adapter
export * from './oidc-provider/index.js';

// Re-export base adapter for convenience
export { BaseOAuthAdapter } from '../base-adapter.js';
export type { ProviderConfig, TokenResponse, OAuthError, ProviderQuirks } from '../types.js';
