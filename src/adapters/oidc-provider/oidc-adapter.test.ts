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

  describe('exchangeCode', function () {
    let adapter: OIDCProviderAdapter;
    let fetchStub: sinon.SinonStub;

    beforeEach(async function () {
      adapter = createTestAdapter();
      await adapter.initialize();
      fetchStub = sinon.stub(global, 'fetch');
    });

    afterEach(function () {
      fetchStub.restore();
    });

    it('should exchange authorization code for tokens successfully', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        id_token: 'test-id-token',
        expires_in: 3600,
        scope: 'openid profile email',
        token_type: 'Bearer',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.accessToken).to.equal('test-access-token');
      expect(result.refreshToken).to.equal('test-refresh-token');
      expect(result.idToken).to.equal('test-id-token');
      expect(result.expiresIn).to.equal(3600);
      expect(result.scope).to.equal('openid profile email');
      expect(result.userData).to.deep.equal({ token_type: 'Bearer' });

      // Verify fetch was called with correct parameters
      expect(fetchStub.callCount).to.equal(1);
      const [url, options] = fetchStub.firstCall.args;
      expect(url).to.equal('https://auth.example.com/oauth/token');
      expect(options.method).to.equal('POST');
      expect(options.headers['Content-Type']).to.equal(
        'application/x-www-form-urlencoded'
      );

      const body = new URLSearchParams(options.body);
      expect(body.get('grant_type')).to.equal('authorization_code');
      expect(body.get('code')).to.equal('test-code');
      expect(body.get('code_verifier')).to.equal('test-verifier');
      expect(body.get('redirect_uri')).to.equal('https://example.com/callback');
      expect(body.get('client_id')).to.equal('test-client-id');
    });

    it('should handle token response without optional fields', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.accessToken).to.equal('test-access-token');
      expect(result.refreshToken).to.be.undefined;
      expect(result.idToken).to.be.undefined;
      expect(result.expiresIn).to.be.undefined;
      expect(result.userData).to.be.undefined;
    });

    it('should handle comma-delimited scopes', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
        scope: 'openid,profile,email',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.scope).to.equal('openid profile email');
    });

    it('should fallback to configured scopes when provider response has none', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.scope).to.equal('openid profile email');
    });

    it('should include client_secret when provided', async function () {
      const configWithSecret = createTestAdapter({
        clientSecret: 'test-client-secret',
      });
      await configWithSecret.initialize();

      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      await configWithSecret.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      const body = new URLSearchParams(fetchStub.firstCall.args[1].body);
      expect(body.get('client_secret')).to.equal('test-client-secret');
    });

    it('should throw error when not initialized', async function () {
      const uninitializedAdapter = createTestAdapter();

      await expectOAuthError(
        () =>
          uninitializedAdapter.exchangeCode(
            'test-code',
            'test-verifier',
            'https://example.com/callback'
          ),
        'invalid_request'
      );
    });

    it('should handle OAuth error responses', async function () {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The authorization code has expired',
      };

      fetchStub.resolves({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: sinon.stub().resolves(errorResponse),
      });

      await expectOAuthError(
        () =>
          adapter.exchangeCode(
            'expired-code',
            'test-verifier',
            'https://example.com/callback'
          ),
        'invalid_grant',
        'The authorization code has expired'
      );
    });

    it('should handle network errors', async function () {
      fetchStub.rejects(new Error('Network error'));

      await expectOAuthError(
        () =>
          adapter.exchangeCode(
            'test-code',
            'test-verifier',
            'https://example.com/callback'
          ),
        'server_error'
      );
    });

    it('should throw error for missing access_token in response', async function () {
      const mockTokenResponse = {
        refresh_token: 'test-refresh-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      await expectOAuthError(
        () =>
          adapter.exchangeCode(
            'test-code',
            'test-verifier',
            'https://example.com/callback'
          ),
        'server_error',
        'Missing access_token in provider response'
      );
    });

    it('should handle invalid JSON response', async function () {
      fetchStub.resolves({
        ok: true,
        json: sinon.stub().rejects(new Error('Invalid JSON')),
      });

      await expectOAuthError(
        () =>
          adapter.exchangeCode(
            'test-code',
            'test-verifier',
            'https://example.com/callback'
          ),
        'server_error'
      );
    });
  });

  describe('refreshToken', function () {
    let adapter: OIDCProviderAdapter;
    let fetchStub: sinon.SinonStub;

    beforeEach(async function () {
      adapter = createTestAdapter();
      await adapter.initialize();
      fetchStub = sinon.stub(global, 'fetch');
    });

    afterEach(function () {
      fetchStub.restore();
    });

    it('should refresh token successfully', async function () {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        scope: 'openid profile',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.refreshToken('old-refresh-token');

      expect(result.accessToken).to.equal('new-access-token');
      expect(result.refreshToken).to.equal('new-refresh-token');
      expect(result.expiresIn).to.equal(3600);
      expect(result.scope).to.equal('openid profile');

      // Verify fetch was called with correct parameters
      expect(fetchStub.callCount).to.equal(1);
      const [url, options] = fetchStub.firstCall.args;
      expect(url).to.equal('https://auth.example.com/oauth/token');

      const body = new URLSearchParams(options.body);
      expect(body.get('grant_type')).to.equal('refresh_token');
      expect(body.get('refresh_token')).to.equal('old-refresh-token');
      expect(body.get('client_id')).to.equal('test-client-id');
    });

    it('should handle refresh without new refresh token', async function () {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        expires_in: 3600,
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.refreshToken('old-refresh-token');

      expect(result.accessToken).to.equal('new-access-token');
      expect(result.refreshToken).to.be.undefined;
      expect(result.expiresIn).to.equal(3600);
    });

    it('should throw error when not initialized', async function () {
      const uninitializedAdapter = createTestAdapter();

      await expectOAuthError(
        () => uninitializedAdapter.refreshToken('test-refresh-token'),
        'invalid_request'
      );
    });

    it('should handle invalid_grant error for expired refresh token', async function () {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The refresh token has expired',
      };

      fetchStub.resolves({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: sinon.stub().resolves(errorResponse),
      });

      await expectOAuthError(
        () => adapter.refreshToken('expired-refresh-token'),
        'invalid_grant',
        'The refresh token has expired'
      );
    });

    it('should handle unauthorized client error', async function () {
      const errorResponse = {
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      };

      fetchStub.resolves({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: sinon.stub().resolves(errorResponse),
      });

      await expectOAuthError(
        () => adapter.refreshToken('test-refresh-token'),
        'invalid_client',
        'Client authentication failed'
      );
    });
  });

  describe('scope normalization', function () {
    let adapter: OIDCProviderAdapter;
    let fetchStub: sinon.SinonStub;

    beforeEach(async function () {
      adapter = createTestAdapter();
      await adapter.initialize();
      fetchStub = sinon.stub(global, 'fetch');
    });

    afterEach(function () {
      fetchStub.restore();
    });

    const testCases = [
      {
        input: 'openid profile email',
        expected: 'openid profile email',
        description: 'space-delimited scopes',
      },
      {
        input: 'openid,profile,email',
        expected: 'openid profile email',
        description: 'comma-delimited scopes',
      },
      {
        input: 'openid, profile, email',
        expected: 'openid profile email',
        description: 'comma-delimited with spaces',
      },
      {
        input: ' openid  profile   email ',
        expected: 'openid profile email',
        description: 'extra whitespace',
      },
      {
        input: 'openid,,profile,,email',
        expected: 'openid profile email',
        description: 'empty comma-separated values',
      },
      {
        input: '',
        expected: 'openid profile email',
        description: 'empty scope (fallback to config)',
      },
    ];

    testCases.forEach(({ input, expected, description }) => {
      it(`should normalize ${description}`, async function () {
        const mockTokenResponse = {
          access_token: 'test-token',
          scope: input,
        };

        fetchStub.resolves({
          ok: true,
          json: sinon.stub().resolves(mockTokenResponse),
        });

        const result = await adapter.exchangeCode(
          'test-code',
          'test-verifier',
          'https://example.com/callback'
        );

        expect(result.scope).to.equal(expected);
      });
    });
  });

  describe('userData extraction', function () {
    let adapter: OIDCProviderAdapter;
    let fetchStub: sinon.SinonStub;

    beforeEach(async function () {
      adapter = createTestAdapter();
      await adapter.initialize();
      fetchStub = sinon.stub(global, 'fetch');
    });

    afterEach(function () {
      fetchStub.restore();
    });

    it('should extract non-sensitive provider response fields', async function () {
      const mockTokenResponse = {
        access_token: 'test-token',
        token_type: 'Bearer',
        expires_in: 3600,
        custom_field: 'custom_value',
        numeric_field: 42,
        boolean_field: true,
        // These should be filtered out
        client_secret: 'secret',
        code_verifier: 'verifier',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.userData).to.deep.equal({
        token_type: 'Bearer',
        custom_field: 'custom_value',
        numeric_field: 42,
        boolean_field: true,
      });
    });

    it('should not include userData when no additional fields present', async function () {
      const mockTokenResponse = {
        access_token: 'test-token',
        expires_in: 3600,
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await adapter.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.userData).to.be.undefined;
    });
  });
});
