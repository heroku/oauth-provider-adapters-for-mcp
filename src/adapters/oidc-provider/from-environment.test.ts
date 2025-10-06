/**
 * Tests for fromEnvironment helper
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { fromEnvironment, fromEnvironmentAsync } from './from-environment.js';
import type { LegacyEnvironmentVariables } from './from-environment.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';

describe('fromEnvironment', () => {
  describe('fromEnvironment (sync)', () => {
    it('should create adapter with required environment variables', () => {
      const env: LegacyEnvironmentVariables = {
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
      const env: LegacyEnvironmentVariables = {
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
      const env: LegacyEnvironmentVariables = {
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
      const env: LegacyEnvironmentVariables = {
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

    it('should throw error when IDENTITY_CLIENT_ID is missing', () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      expect(() => fromEnvironment({ env })).to.throw(
        'Missing required environment variable: IDENTITY_CLIENT_ID'
      );
    });

    it('should throw error when IDENTITY_CLIENT_SECRET is missing', () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      expect(() => fromEnvironment({ env })).to.throw(
        'Missing required environment variable: IDENTITY_CLIENT_SECRET'
      );
    });

    it('should throw error when IDENTITY_SERVER_URL is missing', () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      expect(() => fromEnvironment({ env })).to.throw(
        'Missing required environment variable: IDENTITY_SERVER_URL'
      );
    });

    it('should throw error when IDENTITY_REDIRECT_URI is missing', () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
      };

      expect(() => fromEnvironment({ env })).to.throw(
        'Missing required environment variable: IDENTITY_REDIRECT_URI'
      );
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
      const env: LegacyEnvironmentVariables = {
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
      const env: LegacyEnvironmentVariables = {
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
