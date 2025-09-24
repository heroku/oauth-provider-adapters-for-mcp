/**
 * Common test utilities and helpers
 * Reduces duplication across test files
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { OIDCProviderAdapter } from '../adapters/oidc-provider/oidc-adapter.js';
import { testConfigs, oidcMetadata } from '../fixtures/test-data.js';
import type { OIDCProviderConfig } from '../adapters/oidc-provider/types.js';

/**
 * Helper for testing OAuth error patterns
 */
export async function expectOAuthError(
  fn: () => Promise<any>,
  expectedError: string,
  expectedDescription?: string
): Promise<void> {
  try {
    await fn();
    expect.fail('Expected to throw');
  } catch (err: any) {
    expect(err.error).to.equal(expectedError);
    if (expectedDescription) {
      expect(err.error_description).to.include(expectedDescription);
    }
  }
}

/**
 * Helper for testing constructor validation errors
 * Simple wrapper for sync error testing
 */
export function expectToThrow(fn: () => any, expectedMessage: string): void {
  expect(fn).to.throw(expectedMessage);
}

/**
 * Helper for setting up and tearing down sinon stubs
 */
export function setupSinonStubs(): () => void {
  sinon.stub(console, 'info');
  return () => sinon.restore();
}

/**
 * Helper for creating test adapters with default config
 */
export function createTestAdapter(
  config?: Partial<OIDCProviderConfig>
): OIDCProviderAdapter {
  return new OIDCProviderAdapter({
    ...testConfigs.valid,
    metadata: oidcMetadata.minimal,
    ...config,
  } as OIDCProviderConfig);
}
