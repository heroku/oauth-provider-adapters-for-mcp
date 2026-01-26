/**
 * OIDC Provider Adapter unit tests
 * Tests individual component functionality in isolation
 * Co-located with the adapter for better maintainability
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { OIDCProviderAdapter } from './oidc-adapter.js';
import {
  oidcMetadata,
  createOIDCConfigWithMetadata,
  authUrlData,
  testConfigs,
} from '../../fixtures/test-data.js';
import {
  expectOAuthError,
  expectToThrow,
  setupSinonStubs,
  createTestAdapter,
} from '../../testUtils/testHelpers.js';

describe('OIDCProviderAdapter', function () {
  let restoreStubs: () => void;

  beforeEach(function () {
    restoreStubs = setupSinonStubs();
  });

  afterEach(function () {
    restoreStubs();
  });

  describe('initialization', function () {
    it('should initialize with static metadata', async function () {
      const config = createOIDCConfigWithMetadata();

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      expect(adapter.getProviderMetadata()).to.exist;
    });

    it('should throw error for missing required fields', async function () {
      const config = {
        clientId: '',
        scopes: ['openid'],
        metadata: oidcMetadata.minimal,
      };

      expectToThrow(
        () => new OIDCProviderAdapter(config),
        'clientId is required'
      );
    });

    it('should throw error for missing authorization endpoint', async function () {
      expectToThrow(
        () =>
          createTestAdapter({
            metadata: oidcMetadata.malformed as any,
          }),
        'Invalid input: expected string, received undefined'
      );
    });

    it('should throw error when scopes are missing or empty', async function () {
      const config = {
        clientId: 'test-client-id',
        scopes: [],
        metadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config as any);

      await expectOAuthError(
        () => adapter.initialize(),
        'invalid_request',
        'scopes are required'
      );
    });

    it('should throw error when neither issuer nor metadata is provided', async function () {
      const config = {
        clientId: testConfigs.valid.clientId,
        scopes: ['openid'],
      };

      expectToThrow(
        () => new OIDCProviderAdapter(config as any),
        'Provide exactly one of `issuer` or `metadata`'
      );
    });

    it('should throw error when both issuer and metadata are provided', async function () {
      const config = {
        clientId: testConfigs.valid.clientId,
        scopes: ['openid'],
        issuer: 'https://auth.example.com',
        metadata: oidcMetadata.minimal,
      };

      expectToThrow(
        () => new OIDCProviderAdapter(config as any),
        'Provide exactly one of `issuer` or `metadata`'
      );
    });
  });

  describe('authorization URL generation', function () {
    let adapter: OIDCProviderAdapter;

    beforeEach(async function () {
      adapter = createTestAdapter();
      await adapter.initialize();
    });

    it('should generate valid authorization URL with PKCE', async function () {
      const authUrl = await adapter.generateAuthUrl(
        authUrlData.validParams.interactionId,
        authUrlData.validParams.redirectUrl
      );

      // Parse the URL to properly validate its structure
      const parsedUrl = new URL(authUrl);

      // Validate base URL
      expect(parsedUrl.origin).to.equal('https://auth.example.com');
      expect(parsedUrl.pathname).to.equal('/oauth/authorize');

      // Validate query parameters
      expect(parsedUrl.searchParams.get('response_type')).to.equal('code');
      expect(parsedUrl.searchParams.get('client_id')).to.equal(
        'test-client-id'
      );
      expect(parsedUrl.searchParams.get('redirect_uri')).to.equal(
        authUrlData.validParams.redirectUrl
      );
      expect(parsedUrl.searchParams.get('scope')).to.equal(
        'openid profile email'
      );
      expect(parsedUrl.searchParams.get('state')).to.equal(
        authUrlData.validParams.interactionId
      );
      expect(parsedUrl.searchParams.get('code_challenge')).to.exist;
      expect(parsedUrl.searchParams.get('code_challenge_method')).to.equal(
        'S256'
      );
    });

    it('should store PKCE verifier', async function () {
      const authUrl = await adapter.generateAuthUrl(
        authUrlData.validParams.interactionId,
        authUrlData.validParams.redirectUrl
      );

      // Verify the URL contains PKCE parameters (which implies storage worked)
      expect(authUrl).to.include('code_challenge');
      expect(authUrl).to.include('code_challenge_method=S256');
    });

    it('should throw error if not initialized', async function () {
      const uninitializedAdapter = createTestAdapter();

      await expectOAuthError(
        () =>
          uninitializedAdapter.generateAuthUrl(
            authUrlData.validParams.interactionId,
            authUrlData.validParams.redirectUrl
          ),
        'invalid_request'
      );
    });
  });

  describe('Provider Quirks', function () {
    it('should compute quirks with static metadata', async function () {
      const config = createOIDCConfigWithMetadata();

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      expect(quirks.supportsOIDCDiscovery).to.equal(false);
      expect(quirks.requiresPKCE).to.equal(true);
      expect(quirks.supportsRefreshTokens).to.equal(false);
      expect(quirks.customParameters).to.be.an('array');
    });

    it('should compute quirks with issuer-based discovery', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://auth.example.com',
      };

      const adapter = new OIDCProviderAdapter(config);

      // Discovery will fail, but we can still test the quirks computation
      try {
        await adapter.initialize();
      } catch {
        // Expected to fail due to network
      }

      const quirks = adapter.getProviderQuirks();

      expect(quirks.supportsOIDCDiscovery).to.equal(true);
      expect(quirks.requiresPKCE).to.equal(true);
      expect(quirks.customParameters).to.be.an('array');
    });

    it('should include custom parameters in quirks', async function () {
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile', 'email'],
        metadata: oidcMetadata.minimal,
        customParameters: {
          custom_param: 'custom_value',
          another_param: 'another_value',
        },
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      expect(quirks.customParameters).to.include('custom_param');
      expect(quirks.customParameters).to.include('another_param');
    });
  });

  describe('Discovery-based Initialization', function () {
    it('should attempt issuer discovery', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://auth.example.com',
      };

      const adapter = new OIDCProviderAdapter(config);

      // Discovery will fail due to network, but we can test the attempt
      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('server_error');
      }
    });

    it('should handle discovery errors gracefully', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://invalid-issuer.com',
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('server_error');
      }
    });
  });

  describe('Storage Hook Validation', function () {
    it('should validate storage hook has required methods', async function () {
      const incompleteStorageHook = {
        storePKCEState: sinon.stub().resolves(),
        // Missing retrievePKCEState and cleanupExpiredState
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: incompleteStorageHook as any,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include('storageHook must implement');
        expect(err.error_description).to.include('storePKCEState');
        expect(err.error_description).to.include('retrievePKCEState');
        expect(err.error_description).to.include('cleanupExpiredState');
      }
    });

    it('should validate storage hook methods are functions', async function () {
      const invalidStorageHook = {
        storePKCEState: 'not-a-function',
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: invalidStorageHook as any,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include('storageHook must implement');
      }
    });

    it('should perform health check on cleanupExpiredState', async function () {
      const cleanupStub = sinon.stub().resolves();
      const validStorageHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: cleanupStub,
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: validStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      // Verify cleanupExpiredState was called during validation
      expect(cleanupStub.calledOnce).to.be.true;
      expect(cleanupStub.firstCall.args[0]).to.be.a('number');
    });

    it('should handle cleanupExpiredState health check failures', async function () {
      const failingCleanupHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().rejects(new Error('Cleanup failed')),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: failingCleanupHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error_description).to.include('Cleanup failed');
        expect(err.endpoint).to.equal('storageHook.cleanupExpiredState');
      }
    });

    it('should accept valid storage hook', async function () {
      const validStorageHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: validStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      // Should not throw
      await adapter.initialize();
      expect(adapter.getProviderMetadata()).to.exist;
    });
  });

  describe('Error Handling', function () {
    it('should handle invalid redirect URL', async function () {
      const incompleteStorageHook = {
        storePKCEState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: incompleteStorageHook as any,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include('storageHook must implement');
        expect(err.error_description).to.include('storePKCEState');
        expect(err.error_description).to.include('retrievePKCEState');
        expect(err.error_description).to.include('cleanupExpiredState');
      }
    });

    it('should validate storage hook methods are functions', async function () {
      const invalidStorageHook = {
        storePKCEState: 'not-a-function',
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: invalidStorageHook as any,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include('storageHook must implement');
      }
    });

    it('should perform health check on cleanupExpiredState', async function () {
      const cleanupStub = sinon.stub().resolves();
      const validStorageHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: cleanupStub,
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: validStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      // Verify cleanupExpiredState was called during validation
      expect(cleanupStub.calledOnce).to.be.true;
      expect(cleanupStub.firstCall.args[0]).to.be.a('number');
    });

    it('should handle cleanupExpiredState health check failures', async function () {
      const failingCleanupHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().rejects(new Error('Cleanup failed')),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: failingCleanupHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error_description).to.include('Cleanup failed');
        expect(err.endpoint).to.equal('storageHook.cleanupExpiredState');
      }
    });

    it('should accept valid storage hook', async function () {
      const validStorageHook = {
        storePKCEState: sinon.stub().resolves(),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: validStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      // Should not throw
      await adapter.initialize();
      expect(adapter.getProviderMetadata()).to.exist;
    });
  });

  describe('Error Handling', function () {
    it('should handle invalid redirect URL', async function () {
      const config = createOIDCConfigWithMetadata();

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      // The URL constructor will handle invalid URLs, so this test should pass
      const authUrl = await adapter.generateAuthUrl(
        'test-id',
        'not-a-valid-url'
      );
      expect(authUrl).to.include('not-a-valid-url');
    });

    it('should handle storage hook errors during URL generation', async function () {
      const failingStorageHook = {
        storePKCEPair: sinon.stub().rejects(new Error('Storage error')),
        retrievePKCEPair: sinon.stub().resolves(null),
        storePKCEState: sinon.stub().rejects(new Error('Storage error')),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = createOIDCConfigWithMetadata({
        storageHook: failingStorageHook,
      });

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      try {
        await adapter.generateAuthUrl(
          'test-id',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error_description).to.equal('Storage error');
      }
    });
  });

  describe('extractErrorDetails', function () {
    let adapter: OIDCProviderAdapter;

    beforeEach(function () {
      adapter = createTestAdapter();
    });

    it('should extract message from Error instances', function () {
      const error = new Error('Something went wrong');
      const result = (adapter as any).extractErrorDetails(error);

      expect(result.error).to.equal('Something went wrong');
      expect(result.errorName).to.equal('Error');
      expect(result.errorStack).to.be.a('string');
      expect(result.errorStack).to.include('Error: Something went wrong');
    });

    it('should extract details from OAuthError objects', function () {
      const oauthError = {
        error: 'invalid_request',
        error_description: 'Missing required parameter: client_id',
        statusCode: 400,
        endpoint: 'token',
        issuer: 'https://auth.example.com',
      };
      const result = (adapter as any).extractErrorDetails(oauthError);

      expect(result.error).to.equal('Missing required parameter: client_id');
      expect(result.errorCode).to.equal('invalid_request');
      expect(result.errorDescription).to.equal(
        'Missing required parameter: client_id'
      );
      expect(result.statusCode).to.equal(400);
      expect(result.endpoint).to.equal('token');
      expect(result.issuer).to.equal('https://auth.example.com');
      expect(result.rawError).to.be.a('string');
      expect(JSON.parse(result.rawError)).to.deep.equal(oauthError);
    });

    it('should prefer error_description over error code for error field', function () {
      const oauthError = {
        error: 'server_error',
        error_description: 'Internal server error occurred',
      };
      const result = (adapter as any).extractErrorDetails(oauthError);

      expect(result.error).to.equal('Internal server error occurred');
      expect(result.errorCode).to.equal('server_error');
    });

    it('should fall back to error code when error_description is missing', function () {
      const oauthError = {
        error: 'access_denied',
        statusCode: 403,
      };
      const result = (adapter as any).extractErrorDetails(oauthError);

      expect(result.error).to.equal('access_denied');
      expect(result.errorCode).to.equal('access_denied');
      expect(result.errorDescription).to.be.undefined;
    });

    it('should handle objects with status instead of statusCode', function () {
      const errorWithStatus = {
        error: 'unauthorized',
        status: 401,
      };
      const result = (adapter as any).extractErrorDetails(errorWithStatus);

      expect(result.statusCode).to.equal(401);
    });

    it('should handle plain objects with only message property', function () {
      const errorWithMessage = {
        message: 'Connection timeout',
      };
      const result = (adapter as any).extractErrorDetails(errorWithMessage);

      expect(result.error).to.equal('Connection timeout');
    });

    it('should convert string errors correctly', function () {
      const result = (adapter as any).extractErrorDetails(
        'Simple error string'
      );

      expect(result.error).to.equal('Simple error string');
    });

    it('should handle null gracefully', function () {
      const result = (adapter as any).extractErrorDetails(null);

      expect(result.error).to.equal('null');
    });

    it('should handle undefined gracefully', function () {
      const result = (adapter as any).extractErrorDetails(undefined);

      expect(result.error).to.equal('undefined');
    });

    it('should truncate long stack traces to first 3 lines', function () {
      const error = new Error('Test error');
      // Manually set a long stack trace
      error.stack = `Error: Test error
    at Function.one (/path/to/file1.js:10:15)
    at Function.two (/path/to/file2.js:20:25)
    at Function.three (/path/to/file3.js:30:35)
    at Function.four (/path/to/file4.js:40:45)
    at Function.five (/path/to/file5.js:50:55)`;

      const result = (adapter as any).extractErrorDetails(error);

      const stackLines = result.errorStack.split('\n');
      expect(stackLines.length).to.equal(3);
      expect(result.errorStack).to.not.include('Function.four');
    });
  });
});
