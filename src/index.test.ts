/**
 * Test file for mcp-oauth-provider-adapters
 * Uses Mocha with c8 coverage
 * Co-located with the main module for better maintainability
 */

import { expect } from 'chai';
import { describe, it } from 'mocha';

// Import the module being tested
import { version, BaseOAuthAdapter, OIDCProviderAdapter } from './index.js';
import { moduleData } from './fixtures/test-data.js';

describe('MCP OAuth Provider Adapters', () => {
  it('should export all required modules and properties', async () => {
    // Test version
    expect(version).to.be.a('string');
    expect(version).to.equal(moduleData.expectedVersion);
    expect(version).to.not.be.empty;

    // Test class exports
    expect(BaseOAuthAdapter).to.be.a('function');
    expect(OIDCProviderAdapter).to.be.a('function');

    // Test default export
    const module = await import('./index.js');
    expect(module.default).to.be.an('object');
    expect(module.default).to.have.property('version');
    expect(module.default.version).to.equal(moduleData.expectedVersion);

    // Test all exports are present
    moduleData.expectedExports.forEach((exportName: string) => {
      expect(module).to.have.property(exportName);
    });
  });
});
