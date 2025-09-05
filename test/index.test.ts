/**
 * Test file for mcp-oauth-provider-adapters
 * Uses Mocha with c8 coverage
 */

import { expect } from 'chai';
import { describe, it} from 'mocha';

// Import the module being tested
import { version, greet } from '../src/index.js';

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

  describe('greet function', () => {
    it('should return a greeting message', () => {
      const result = greet('World');
      expect(result).to.be.a('string');
      expect(result).to.equal('Hello, World!');
    });

    it('should handle different names', () => {
      const testCases = [
        { input: 'Alice', expected: 'Hello, Alice!' },
        { input: 'Bob', expected: 'Hello, Bob!' },
        { input: 'TypeScript', expected: 'Hello, TypeScript!' },
        { input: '', expected: 'Hello, !' }
      ];

      testCases.forEach(({ input, expected }) => {
        const result = greet(input);
        expect(result).to.equal(expected);
      });
    });

    it('should handle special characters in names', () => {
      const specialNames = ['@user', 'user-name', 'user_name', 'user.name'];
      
      specialNames.forEach(name => {
        const result = greet(name);
        expect(result).to.be.a('string');
        expect(result).to.include(name);
        expect(result).to.include('Hello');
      });
    });
  });

  describe('default export', () => {
    it('should export a default object', async () => {
      const module = await import('../src/index.js');
      expect(module.default).to.be.an('object');
    });

    it('should have version and greet properties', async () => {
      const module = await import('../src/index.js');
      const defaultExport = module.default;
      
      expect(defaultExport).to.have.property('version');
      expect(defaultExport).to.have.property('greet');
      expect(defaultExport.version).to.equal(version);
      expect(defaultExport.greet).to.equal(greet);
    });
  });

  describe('module structure', () => {
    it('should be importable as ES module', async () => {
      const module = await import('../src/index.js');
      
      expect(module).to.have.property('version');
      expect(module).to.have.property('greet');
      expect(module).to.have.property('default');
    });

    it('should have correct function types', () => {
      expect(greet).to.be.a('function');
      expect(greet.length).to.equal(1); // One parameter
    });
  });
});
