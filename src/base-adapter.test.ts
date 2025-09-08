import { expect } from 'chai';
import { BaseOAuthAdapter } from './base-adapter.js';
import type { ProviderConfig } from './types.js';

describe('BaseOAuthAdapter', () => {
  const mockConfig: ProviderConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    issuer: 'https://example.com',
    scopes: ['openid', 'profile'],
    customParameters: {
      audience: 'test-audience',
    },
  };

  describe('constructor', () => {
    it('should store config as protected readonly property', () => {
      class TestAdapter extends BaseOAuthAdapter {
        public getConfig() {
          return this.config;
        }
      }

      const adapter = new TestAdapter(mockConfig);
      const storedConfig = adapter.getConfig();

      expect(storedConfig).to.equal(mockConfig);
      expect(storedConfig.clientId).to.equal('test-client-id');
      expect(storedConfig.scopes).to.deep.equal(['openid', 'profile']);
      expect(storedConfig.customParameters?.audience).to.equal('test-audience');
    });

    it('should be constructible with minimal config', () => {
      const minimalConfig: ProviderConfig = {
        clientId: 'minimal-client',
        metadata: { authorization_endpoint: 'https://auth.example.com' },
        scopes: ['read'],
      };

      class MinimalTestAdapter extends BaseOAuthAdapter {}

      expect(() => new MinimalTestAdapter(minimalConfig)).to.not.throw();
    });
  });

  describe('abstract class behavior', () => {
    it('should be abstract and not directly instantiable', () => {
      // TypeScript compile-time check - this should fail compilation if uncommented:
      // const adapter = new BaseOAuthAdapter(mockConfig);

      // Runtime verification that the class is meant to be abstract
      expect(() => {
        // @ts-expect-error Testing abstract class instantiation
        new BaseOAuthAdapter(mockConfig);
      }).to.throw();
    });

    it('should require subclasses to implement abstract methods', () => {
      // This is a placeholder for future abstract method enforcement
      // When abstract methods are added in subsequent tasks, they will be tested here
      class IncompleteAdapter extends BaseOAuthAdapter {}

      const adapter = new IncompleteAdapter(mockConfig);
      expect(adapter).to.be.instanceOf(BaseOAuthAdapter);

      // Future abstract methods will throw when called on incomplete implementations
      // Example placeholder for when initialize() becomes abstract:
      // expect(() => adapter.initialize()).toThrow('Method not implemented');
    });
  });
});
