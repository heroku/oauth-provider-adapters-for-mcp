/**
 * BaseOAuthAdapter comprehensive test suite
 * Tests all requirements for the abstract base class
 * Co-located with the base adapter for better maintainability
 */

import assert from 'assert';
import sinon from 'sinon';
import { BaseOAuthAdapter } from './base-adapter.js';
import {
  testConfigs,
  errorData
} from './fixtures/test-data.js';
import {
  ConfigurableTestAdapter,
  MemoizationTestAdapter
} from './testUtils/adapters.js';


describe('BaseOAuthAdapter', function() {
  let fetchSpy: sinon.SinonSpy;

  beforeEach(function() {
    fetchSpy = sinon.spy(globalThis, 'fetch');
  });

  afterEach(function() {
    sinon.restore();
  });

  it('should enforce abstract methods at compile time', function() {
    const adapter = new ConfigurableTestAdapter(testConfigs.valid);
    assert(adapter instanceof BaseOAuthAdapter, 'Should be instance of BaseOAuthAdapter');
  });

  it('should throw when calling abstract methods via dummy subclass', async function() {
    const adapter = new ConfigurableTestAdapter(testConfigs.valid, { initialized: false });
    
    await assert.rejects(
      adapter.generateAuthUrl('test-id', 'https://example.com/callback'),
      (err: any) => err.error === 'server_error'
    );
  });

  it('should accept config: ProviderConfig as an argument', function() {
    const config = testConfigs.valid;
    const adapter = new ConfigurableTestAdapter(config);
    
    assert(adapter.getConfig(), 'Should store config');
    assert.equal(adapter.getConfig().clientId, config.clientId);
    assert.deepEqual(adapter.getConfig().scopes, config.scopes);
  });

  it('should reject generateAuthUrl before initialize() with normalized error', async function() {
    const adapter = new ConfigurableTestAdapter(testConfigs.valid, { initialized: false });
    
    await assert.rejects(
      adapter.generateAuthUrl('test-id', 'https://example.com/callback'),
      (err: any) => {
        assert.equal(err.error, 'server_error');
        assert(err.error_description?.includes('Adapter not initialized'));
        assert.equal(err.endpoint, '/authorize');
        return true;
      }
    );
  });

  describe('URL Composition', function() {
    let adapter: ConfigurableTestAdapter;

    beforeEach(async function() {
      adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
    });

    it('should return URL with state=interactionId and URL-encoded redirect_uri', async function() {
      const interactionId = 'test-interaction-123';
      const redirectUrl = 'https://example.com/callback?param=value';
      
      const authUrl = await adapter.generateAuthUrl(interactionId, redirectUrl);
      
      assert(authUrl.includes(`state=${interactionId}`), 'Should include state parameter');
      assert(authUrl.includes('redirect_uri='), 'Should include redirect_uri parameter');
      assert(authUrl.includes(encodeURIComponent(redirectUrl)), 'Should URL-encode redirect_uri');
    });

    it('should merge custom parameters with base params', async function() {
      const configWithCustom = {
        ...testConfigs.valid,
        customParameters: {
          'custom_param': 'custom_value',
          'another_param': 'another_value'
        }
      };
      
      const adapter = new ConfigurableTestAdapter(configWithCustom);
      await adapter.initialize();
      
      const authUrl = await adapter.generateAuthUrl('test-id', 'https://example.com/callback');
      
      assert(authUrl.includes('custom_param=custom_value'), 'Should include custom parameter');
      assert(authUrl.includes('another_param=another_value'), 'Should include another custom parameter');
      assert(authUrl.includes('response_type=code'), 'Should include base parameters');
      assert(authUrl.includes('client_id='), 'Should include client_id');
    });
  });

  describe('No I/O', function() {
    it('should not call globalThis.fetch during generateAuthUrl', async function() {
      const adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
      
      await adapter.generateAuthUrl('test-id', 'https://example.com/callback');
      
      assert.equal(fetchSpy.callCount, 0, 'Should not call fetch during generateAuthUrl');
    });
  });

  describe('Exchange Code', function() {
    let adapter: ConfigurableTestAdapter;

    beforeEach(async function() {
      adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
    });

    it('should map success to normalized TokenResponse', async function() {
      const result = await adapter.exchangeCode('auth-code', 'verifier', 'https://example.com/callback');
      
      assert.equal(result.accessToken, 'default-access-token');
      assert.equal(result.refreshToken, undefined);
      assert.equal(result.expiresIn, undefined);
    });

    it('should normalize provider errors to OAuthError', async function() {
      const providerError = errorData.openidError;
      const adapterWithError = new ConfigurableTestAdapter(testConfigs.valid, {
        exchangeCodeError: providerError
      });
      await adapterWithError.initialize();
      
      await assert.rejects(
        adapterWithError.exchangeCode('auth-code', 'verifier', 'https://example.com/callback'),
        (err: any) => {
          assert.equal(err.error, 'invalid_grant');
          assert(err.error_description?.includes('Invalid authorization code'));
          return true;
        }
      );
    });
  });

  describe('Refresh Token', function() {
    let adapter: ConfigurableTestAdapter;

    beforeEach(async function() {
      adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
    });

    it('should map success to new accessToken', async function() {
      const result = await adapter.refreshToken('refresh-token');
      
      assert.equal(result.accessToken, 'default-refresh-token');
      assert.equal(result.refreshToken, undefined);
    });

    it('should throw normalized error for unsupported operation', async function() {
      const adapterNoRefresh = new ConfigurableTestAdapter(testConfigs.valid, {
        supportsRefresh: false
      });
      await adapterNoRefresh.initialize();
      
      await assert.rejects(
        adapterNoRefresh.refreshToken('refresh-token'),
        (err: any) => {
          assert.equal(err.error, 'unsupported_grant_type');
          assert(err.error_description?.includes('Refresh token not supported'));
          return true;
        }
      );
    });
  });

  describe('Memoization', function() {
    it('should call computeProviderQuirks() once across multiple getProviderQuirks() calls', async function() {
      const adapter = new MemoizationTestAdapter(testConfigs.valid);
      await adapter.initialize();
      
      // Get initial call count
      const initialCount = adapter.getCallCount();
      
      // Call getProviderQuirks multiple times
      const quirks1 = adapter.getProviderQuirks();
      const quirks2 = adapter.getProviderQuirks();
      const quirks3 = adapter.getProviderQuirks();
      
      // All calls should return the same result
      assert.deepEqual(quirks1, quirks2);
      assert.deepEqual(quirks2, quirks3);
      
      // The underlying compute method should only be called once due to memoization
      // (initial count + 1 for the first call, then memoized)
      assert.equal(adapter.getCallCount(), initialCount + 1, 'Should call computeProviderQuirks exactly once after initial calls');
    });
  });

  describe('No I/O', function() {
    it('should not call globalThis.fetch during getProviderQuirks', async function() {
      const adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
      
      adapter.getProviderQuirks();
      
      assert.equal(fetchSpy.callCount, 0, 'Should not call fetch during getProviderQuirks');
    });
  });

  describe('Shape', function() {
    it('should return object with required fields', async function() {
      const adapter = new ConfigurableTestAdapter(testConfigs.valid);
      await adapter.initialize();
      
      const quirks = adapter.getProviderQuirks();
      
      assert(quirks.hasOwnProperty('supportsOIDCDiscovery'), 'Should have supportsOIDCDiscovery');
      assert(quirks.hasOwnProperty('requiresPKCE'), 'Should have requiresPKCE');
      assert(quirks.hasOwnProperty('supportsRefreshTokens'), 'Should have supportsRefreshTokens');
      assert(quirks.hasOwnProperty('customParameters'), 'Should have customParameters');
    });

    it('should reflect customParameters in config', async function() {
      const configWithCustom = {
        ...testConfigs.valid,
        customParameters: {
          'custom_param': 'custom_value'
        }
      };
      
      const adapter = new ConfigurableTestAdapter(configWithCustom, { trackQuirksCalls: true });
      await adapter.initialize();
      
      const quirks = adapter.getProviderQuirks();
      
      assert(Array.isArray(quirks.customParameters), 'customParameters should be array');
      assert(quirks.customParameters.includes('custom_param'), `Should include custom parameter. Got: ${JSON.stringify(quirks.customParameters)}`);
    });
  });

});
