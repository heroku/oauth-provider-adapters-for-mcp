import type { ProviderConfig } from './types.js';

/**
 * Abstract base class that all OAuth provider adapters must implement.
 * Establishes the core contract for initialization, authorization URL generation,
 * token exchange, refresh, and provider quirks metadata.
 */
export abstract class BaseOAuthAdapter {
  /**
   * Provider configuration stored as protected readonly for subclass access
   */
  protected readonly config: ProviderConfig;

  /**
   * Creates a new BaseOAuthAdapter instance
   *
   * @param config - Provider-specific configuration including client credentials, scopes, and endpoints
   */
  public constructor(config: ProviderConfig) {
    if (new.target === BaseOAuthAdapter) {
      throw new TypeError(
        'BaseOAuthAdapter is abstract and cannot be instantiated directly'
      );
    }
    this.config = config;
  }
}
