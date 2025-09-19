/**
 * OIDC Provider Adapter unit tests
 * Tests individual component functionality in isolation
 * Co-located with the adapter for better maintainability
 */

import assert from 'assert';
import sinon from 'sinon';
import { OIDCProviderAdapter } from './oidc-adapter.js';
import { MockPKCEStorageHook } from './types.js';
import {
  oidcMetadata,
  testConfigs,
  authUrlData,
} from '../../fixtures/test-data.js';

describe('OIDCProviderAdapter', function () {
  let mockStorageHook: MockPKCEStorageHook;

  beforeEach(function () {
    mockStorageHook = new MockPKCEStorageHook();
    sinon.stub(console, 'info');
  });

  afterEach(function () {
    sinon.restore();
  });

  describe('initialization', function () {
    it('should initialize with static metadata', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      assert(adapter.getProviderMetadata(), 'Should have provider metadata');
    });

    it('should throw error for missing required fields', async function () {
      const config = {
        clientId: '',
        scopes: ['openid'],
        metadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config);

      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'invalid_request'
      );
    });

    it('should throw error for missing authorization endpoint', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.malformed as any,
      };

      const adapter = new OIDCProviderAdapter(config);

      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'invalid_request'
      );
    });
  });

  describe('authorization URL generation', function () {
    let adapter: OIDCProviderAdapter;

    beforeEach(async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: mockStorageHook,
      };

      adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
    });

    it('should generate valid authorization URL with PKCE', async function () {
      const authUrl = await adapter.generateAuthUrl(
        authUrlData.validParams.interactionId,
        authUrlData.validParams.redirectUrl
      );

      // Check for expected URL parts
      authUrlData.expectedUrlParts.forEach((part) => {
        assert(authUrl.includes(part), `Should contain ${part}`);
      });
    });

    it('should store PKCE verifier', async function () {
      await adapter.generateAuthUrl(
        authUrlData.validParams.interactionId,
        authUrlData.validParams.redirectUrl
      );

      const verifier = await mockStorageHook.retrievePKCEState(
        authUrlData.validParams.interactionId,
        authUrlData.validParams.interactionId
      );
      assert(verifier, 'Should store PKCE verifier');
      assert(typeof verifier === 'string', 'Verifier should be string');
    });

    it('should throw error if not initialized', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
      };
      const uninitializedAdapter = new OIDCProviderAdapter(config);

      await assert.rejects(
        uninitializedAdapter.generateAuthUrl(
          authUrlData.validParams.interactionId,
          authUrlData.validParams.redirectUrl
        ),
        (err: any) => err.error === 'invalid_request'
      );
    });
  });

  describe('Provider Quirks', function () {
    it('should compute quirks with static metadata', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      assert.equal(
        quirks.supportsOIDCDiscovery,
        false,
        'Should not support OIDC discovery with static metadata'
      );
      assert.equal(quirks.requiresPKCE, true, 'Should require PKCE');
      assert.equal(
        quirks.supportsRefreshTokens,
        false,
        'Should not support refresh tokens by default'
      );
      assert(
        Array.isArray(quirks.customParameters),
        'Should have custom parameters array'
      );
    });

    it('should compute quirks with issuer-based discovery', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://auth.example.com',
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      // Discovery will fail, but we can still test the quirks computation
      try {
        await adapter.initialize();
      } catch {
        // Expected to fail due to network
      }

      const quirks = adapter.getProviderQuirks();

      assert.equal(
        quirks.supportsOIDCDiscovery,
        true,
        'Should support OIDC discovery with issuer'
      );
      assert.equal(quirks.requiresPKCE, true, 'Should require PKCE');
      assert(
        Array.isArray(quirks.customParameters),
        'Should have custom parameters array'
      );
    });

    it('should include custom parameters in quirks', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        customParameters: {
          custom_param: 'custom_value',
          another_param: 'another_value',
        },
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      assert(
        quirks.customParameters.includes('custom_param'),
        'Should include custom parameter'
      );
      assert(
        quirks.customParameters.includes('another_param'),
        'Should include another custom parameter'
      );
    });
  });

  describe('Discovery-based Initialization', function () {
    it('should attempt issuer discovery', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://auth.example.com',
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      // Discovery will fail due to network, but we can test the attempt
      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'server_error'
      );
    });

    it('should handle discovery errors gracefully', async function () {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        issuer: 'https://invalid-issuer.com',
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);

      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'server_error'
      );
    });
  });

  describe('Error Handling', function () {
    it('should handle invalid redirect URL', async function () {
      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: mockStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      // The URL constructor will handle invalid URLs, so this test should pass
      const authUrl = await adapter.generateAuthUrl(
        'test-id',
        'not-a-valid-url'
      );
      assert(
        authUrl.includes('not-a-valid-url'),
        'Should include the redirect URL as provided'
      );
    });

    it('should handle storage hook errors', async function () {
      const failingStorageHook = {
        storePKCEPair: sinon.stub().rejects(new Error('Storage error')),
        retrievePKCEPair: sinon.stub().resolves(null),
        storePKCEState: sinon.stub().rejects(new Error('Storage error')),
        retrievePKCEState: sinon.stub().resolves(null),
        cleanupExpiredState: sinon.stub().resolves(),
      };

      const config = {
        ...testConfigs.valid,
        metadata: oidcMetadata.minimal,
        storageHook: failingStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      await assert.rejects(
        adapter.generateAuthUrl('test-id', 'https://example.com/callback'),
        (err: any) => err.message === 'Storage error'
      );
    });
  });
});
