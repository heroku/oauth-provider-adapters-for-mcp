/**
 * Test file for mcp-oauth-provider-adapters
 * Uses Mocha with c8 coverage
 */

import { expect } from 'chai';
import { describe, it} from 'mocha';

// Import the module being tested
import { version} from '../src/index.js';

describe('MCP OAuth Provider Adapters', () => {
  describe('version', () => {
    it('should export a version string', () => {
      expect(version).to.be.a('string');
      expect(version).to.equal('0.0.1');
    });
  });
});
