/**
 * Test file for mcp-oauth-provider-adapters
 * Uses Mocha with c8 coverage
 */

import { expect } from 'chai';
import { describe, it } from 'mocha';

// Import the module being tested
import { version, BaseOAuthAdapter, OIDCProviderAdapter } from '../../dist/cjs/index.js';

describe('MCP OAuth Provider Adapters', () => {
  describe('version', () => {
    it('should export a version string', () => {
      expect(version).to.be.a('string');
      expect(version).to.equal('0.0.1');
    });

    it('should not be empty', () => {
      expect(version).to.not.be.empty;
    });
  });

  describe('exports', () => {
    it('should export BaseOAuthAdapter', () => {
      expect(BaseOAuthAdapter).to.be.a('function');
    });

    it('should export OIDCProviderAdapter', () => {
      expect(OIDCProviderAdapter).to.be.a('function');
    });
  });

  describe('default export', () => {
    it('should export a default object', async () => {
      const module = await import('../../dist/cjs/index.js');
      expect(module.default).to.be.an('object');
    });

    it('should have version property', async () => {
      const module = await import('../../dist/cjs/index.js');
      const defaultExport = module.default;

      expect(defaultExport).to.have.property('version');
      expect(defaultExport.version).to.equal(version);
    });
  });

  describe('module structure', () => {
    it('should be importable as ES module', async () => {
      const module = await import('../../dist/cjs/index.js');

      expect(module).to.have.property('version');
      expect(module).to.have.property('BaseOAuthAdapter');
      expect(module).to.have.property('OIDCProviderAdapter');
      expect(module).to.have.property('default');
    });
  });
});
