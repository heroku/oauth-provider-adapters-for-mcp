/**
 * Tests for fromEnvironment helper
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { fromEnvironment, fromEnvironmentAsync } from './from-environment.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';
import type { LegacyEnvironmentVariables } from './from-environment.js';

describe('fromEnvironment', () => {
  let sandbox: sinon.SinonSandbox;

  beforeEach(() => {
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    sandbox.restore();
  });

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
    });

    it('should create adapter with custom scopes', () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SCOPE: 'openid profile email custom:scope',
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
        defaultScopes: ['openid', 'custom:default'],
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
        storePKCEState: sandbox.stub().resolves(),
        retrievePKCEState: sandbox.stub().resolves('verifier'),
        cleanupExpiredState: sandbox.stub().resolves(),
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
      // Save original env
      const originalEnv = { ...process.env };

      // Set test env vars
      process.env.IDENTITY_CLIENT_ID = 'process-client-id';
      process.env.IDENTITY_CLIENT_SECRET = 'process-client-secret';
      process.env.IDENTITY_SERVER_URL = 'https://process.example.com';
      process.env.IDENTITY_REDIRECT_URI =
        'https://process.example.com/callback';
      process.env.IDENTITY_SCOPE = 'openid custom:scope';

      try {
        const adapter = fromEnvironment();

        expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      } finally {
        // Restore original env
        process.env = originalEnv;
      }
    });
  });

  describe('fromEnvironmentAsync', () => {
    it('should create and initialize adapter', async () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      // Mock the initialize method
      const initializeStub = sandbox
        .stub(OIDCProviderAdapter.prototype, 'initialize')
        .resolves();

      const adapter = await fromEnvironmentAsync({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      expect(initializeStub.calledOnce).to.be.true;
    });

    it('should propagate initialization errors', async () => {
      const env: LegacyEnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
      };

      // Mock the initialize method to throw an error
      const error = new Error('Initialization failed');
      sandbox.stub(OIDCProviderAdapter.prototype, 'initialize').rejects(error);

      try {
        await fromEnvironmentAsync({ env });
        expect.fail('Should have thrown error');
      } catch (err) {
        expect(err).to.equal(error);
      }
    });
  });
});
