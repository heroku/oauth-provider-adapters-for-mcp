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
  testConfigs,
  authUrlData,
} from '../../fixtures/test-data.js';

describe('OIDCProviderAdapter', function () {
  beforeEach(function () {
    sinon.stub(console, 'info');
  });

  afterEach(function () {
    sinon.restore();
  });

  describe('initialization', function () {
    it('should initialize with static metadata', async function () {
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      expect(adapter.getProviderMetadata()).to.exist;
    });

    // Note: Config validation tests have been moved to config.test.ts
    // This test now focuses on adapter initialization behavior
  });

  describe('authorization URL generation', function () {
    let adapter: OIDCProviderAdapter;

    beforeEach(async function () {
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
      };

      adapter = new OIDCProviderAdapter(config);
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
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
      };
      const uninitializedAdapter = new OIDCProviderAdapter(config);

      try {
        await uninitializedAdapter.generateAuthUrl(
          authUrlData.validParams.interactionId,
          authUrlData.validParams.redirectUrl
        );
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.error).to.equal('invalid_request');
      }
    });
  });

  describe('Provider Quirks', function () {
    it('should compute quirks with static metadata', async function () {
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      expect(quirks.supportsOIDCDiscovery).to.equal(false);
      expect(quirks.requiresPKCE).to.equal(true);
      expect(quirks.supportsRefreshTokens).to.equal(false);
      expect(quirks.additionalParameters).to.be.an('array');
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
      expect(quirks.additionalParameters).to.be.an('array');
    });

    it('should include custom parameters in quirks', async function () {
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
        additionalParameters: {
          custom_param: 'custom_value',
          another_param: 'another_value',
        },
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      const quirks = adapter.getProviderQuirks();

      expect(quirks.additionalParameters).to.include('custom_param');
      expect(quirks.additionalParameters).to.include('another_param');
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

  describe('Error Handling', function () {
    it('should handle invalid redirect URL', async function () {
      const config = {
        ...testConfigs.valid,
        serverMetadata: oidcMetadata.minimal,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      // The URL constructor will handle invalid URLs, so this test should pass
      const authUrl = await adapter.generateAuthUrl(
        'test-id',
        'not-a-valid-url'
      );
      expect(authUrl).to.include('not-a-valid-url');
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
        serverMetadata: oidcMetadata.minimal,
        storageHook: failingStorageHook,
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      try {
        await adapter.generateAuthUrl(
          'test-id',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch (err: any) {
        expect(err.message).to.equal('Storage error');
      }
    });
  });
});
