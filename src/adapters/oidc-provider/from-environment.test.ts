/**
 * Tests for fromEnvironment helper
 */

import { expect } from 'chai';
import sinon from 'sinon';
import type { EnvironmentVariables } from './types.js';
import { fromEnvironment, fromEnvironmentAsync } from './from-environment.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';

describe('fromEnvironment', () => {
  describe('fromEnvironment (sync)', () => {
    it('should create adapter with required environment variables', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      const adapter = fromEnvironment({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      // Verify the adapter was created (we can't easily test internal config)
      expect(adapter).to.not.be.null;
    });

    it('should create adapter with custom scopes', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SCOPE: 'openid profile custom-scope',
      };

      const adapter = fromEnvironment({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
    });

    it('should create adapter with custom default scopes', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      const adapter = fromEnvironment({
        env,
        defaultScopes: ['openid', 'custom'],
      });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
    });

    it('should create adapter with storage hook', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      const mockStorageHook = {
        storePKCEState: sinon.stub(),
        retrievePKCEState: sinon.stub(),
        cleanupExpiredState: sinon.stub(),
      };

      const adapter = fromEnvironment({ env, storageHook: mockStorageHook });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
    });

    describe('missing required environment variables', () => {
      const baseEnv: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      // Generate an array of test cases for each variable in the EnvironmentVariables interface
      const cases = Object.keys(baseEnv).map((key) => ({
        missingKey: key as keyof EnvironmentVariables,
        message: `Missing required environment variable: ${key}`,
      }));

      // Run a test case for each variable
      for (const testCase of cases) {
        it(`should throw error when ${testCase.missingKey} is missing`, () => {
          const env: EnvironmentVariables = { ...baseEnv };
          delete env[testCase.missingKey];

          expect(() => fromEnvironment({ env })).to.throw(testCase.message);
        });
      }
    });

    it('should use process.env when env option is not provided', () => {
      const originalEnv = process.env;
      process.env = {
        ...originalEnv,
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      try {
        const adapter = fromEnvironment();
        expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      } finally {
        process.env = originalEnv;
      }
    });
  });

  describe('fromEnvironmentAsync', () => {
    it('should create adapter instance (initialization will be tested separately)', async () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      // Just verify that fromEnvironment creates an adapter,
      // initialization testing is handled in the OIDC adapter tests
      const adapter = fromEnvironment({ env });
      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
    });

    it('should propagate creation errors from fromEnvironment', async () => {
      const env: EnvironmentVariables = {
        // Missing required env vars
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      try {
        await fromEnvironmentAsync({ env });
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.include('IDENTITY_CLIENT_ID');
      }
    });
  });
});
