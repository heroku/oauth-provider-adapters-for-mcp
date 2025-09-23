import { expect } from 'chai';
import type { ProviderConfig } from '../types.js';
import {
  ConfigurableTestAdapter,
  TokenMappingTestAdapter,
  ErrorThrowingTestAdapter,
  RefreshTokenTestAdapter,
  MemoizationTestAdapter,
} from './adapters.js';

describe('Test Adapters', () => {
  const mockConfig: ProviderConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    issuer: 'https://example.com',
    scopes: ['openid', 'profile'],
  };

  // Base methods all adapters should have
  const baseMethods = [
    'initialize',
    'generateAuthUrl',
    'exchangeCode',
    'refreshToken',
    'getProviderQuirks',
  ];

  // Additional methods specific to certain adapters
  const additionalMethods = {
    ConfigurableTestAdapter: ['getConfig', 'exposeNormalizeError'],
    ErrorThrowingTestAdapter: ['exposeNormalizeError'],
    TokenMappingTestAdapter: [],
    RefreshTokenTestAdapter: [],
    MemoizationTestAdapter: ['getCallCount'],
  };

  const testCases = [
    { name: 'ConfigurableTestAdapter', AdapterClass: ConfigurableTestAdapter },
    { name: 'TokenMappingTestAdapter', AdapterClass: TokenMappingTestAdapter },
    {
      name: 'ErrorThrowingTestAdapter',
      AdapterClass: ErrorThrowingTestAdapter,
    },
    { name: 'RefreshTokenTestAdapter', AdapterClass: RefreshTokenTestAdapter },
    { name: 'MemoizationTestAdapter', AdapterClass: MemoizationTestAdapter },
  ];

  testCases.forEach(({ name, AdapterClass }) => {
    describe(name, () => {
      it('should have all required methods', () => {
        const adapter = new AdapterClass(mockConfig);
        const expectedMethods = [
          ...baseMethods,
          ...additionalMethods[name as keyof typeof additionalMethods],
        ];

        expectedMethods.forEach((methodName) => {
          expect(adapter[methodName as keyof typeof adapter]).to.be.a(
            'function',
            `${methodName} should be a function`
          );
        });
      });
    });
  });

  describe('Method functionality smoke tests', () => {
    const smokeTestCases = [
      {
        name: 'ConfigurableTestAdapter',
        AdapterClass: ConfigurableTestAdapter,
        exchangeCodeShouldThrow: false,
        hasExposeNormalizeError: true,
        hasGetConfig: true,
      },
      {
        name: 'TokenMappingTestAdapter',
        AdapterClass: TokenMappingTestAdapter,
        exchangeCodeShouldThrow: false,
        hasExposeNormalizeError: false,
        hasGetConfig: false,
      },
      {
        name: 'ErrorThrowingTestAdapter',
        AdapterClass: ErrorThrowingTestAdapter,
        exchangeCodeShouldThrow: true,
        hasExposeNormalizeError: true,
        hasGetConfig: false,
      },
      {
        name: 'RefreshTokenTestAdapter',
        AdapterClass: RefreshTokenTestAdapter,
        exchangeCodeShouldThrow: false,
        hasExposeNormalizeError: false,
        hasGetConfig: false,
      },
    ];

    smokeTestCases.forEach(
      ({
        name,
        AdapterClass,
        exchangeCodeShouldThrow,
        hasExposeNormalizeError,
        hasGetConfig,
      }) => {
        it(`${name} methods should be callable`, async () => {
          const adapter = new AdapterClass(mockConfig);
          await adapter.initialize();

          // Test common methods
          const authUrl = await adapter.generateAuthUrl(
            'test',
            'http://callback'
          );
          expect(authUrl).to.be.a('string');

          if (exchangeCodeShouldThrow) {
            try {
              await adapter.exchangeCode('code', 'verifier', 'http://callback');
              expect.fail('Should have thrown an error');
            } catch (error) {
              expect(error).to.have.property('statusCode');
            }
          } else {
            const tokenResponse = await adapter.exchangeCode(
              'code',
              'verifier',
              'http://callback'
            );
            expect(tokenResponse).to.have.property('accessToken');
          }

          const refreshResponse = await adapter.refreshToken('refresh-token');
          expect(refreshResponse).to.have.property('accessToken');

          const quirks = adapter.getProviderQuirks();
          expect(quirks).to.have.property('supportsOIDCDiscovery');

          // Test adapter-specific methods
          if (hasGetConfig) {
            const config = (adapter as ConfigurableTestAdapter).getConfig();
            expect(config).to.equal(mockConfig);
          }

          if (hasExposeNormalizeError) {
            const normalizedError = (
              adapter as ConfigurableTestAdapter | ErrorThrowingTestAdapter
            ).exposeNormalizeError('test error', {});
            expect(normalizedError).to.have.property('statusCode');
          }
        });
      }
    );
  });
});
