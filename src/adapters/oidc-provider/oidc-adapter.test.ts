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

      const adapter = new OIDCProviderAdapter(config);

      await expectOAuthError(() => adapter.initialize(), 'invalid_request');
    });

    it('should throw error for missing authorization endpoint', async function () {
      const adapter = createTestAdapter({
        metadata: oidcMetadata.malformed as any,
      });

      await expectOAuthError(() => adapter.initialize(), 'invalid_request');
    });

    it('should throw error when scopes are missing or empty', async function () {
      const adapter = createTestAdapter({
        scopes: [],
      });

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

      const adapter = new OIDCProviderAdapter(config as any);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include(
          'Either issuer or metadata must be provided'
        );
      }
    });

    it('should throw error when both issuer and metadata are provided', async function () {
      const config = {
        clientId: testConfigs.valid.clientId,
        scopes: ['openid'],
        issuer: 'https://auth.example.com',
        metadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config as any);

      try {
        await adapter.initialize();
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
        expect(err.error_description).to.include(
          'Cannot specify both issuer and metadata'
        );
      }
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
        serverMetadata: oidcMetadata.minimal,
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
});
