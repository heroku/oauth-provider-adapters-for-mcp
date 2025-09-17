/**
 * OIDC Provider Adapter unit tests
 * Tests individual component functionality in isolation
 */

import assert from 'assert';
import sinon from 'sinon';
import { OIDCProviderAdapter } from '../../../../dist/cjs/adapters/oidc-provider/oidc-adapter.js';
import { MockPKCEStorageHook } from '../../../../dist/cjs/adapters/oidc-provider/types.js';
import { 
  minimalMetadata, 
  malformedMetadata 
} from '../../../helpers/test-metadata.js';

describe('OIDCProviderAdapter', function() {
  let mockStorageHook: MockPKCEStorageHook;

  beforeEach(function() {
    mockStorageHook = new MockPKCEStorageHook();
    sinon.stub(console, 'info');
  });

  afterEach(function() {
    sinon.restore();
  });

  describe('initialization', function() {
    it('should initialize with static metadata', async function() {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        metadata: minimalMetadata,
        storageHook: mockStorageHook
      };

      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();

      assert(adapter.getProviderMetadata(), 'Should have provider metadata');
    });

    it('should throw error for missing required fields', async function() {
      const config = {
        clientId: '',
        scopes: ['openid'],
        metadata: minimalMetadata
      };

      const adapter = new OIDCProviderAdapter(config);
      
      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'invalid_request'
      );
    });

    it('should throw error for missing authorization endpoint', async function() {
      const config = {
        clientId: 'test-client',
        scopes: ['openid'],
        metadata: malformedMetadata as any
      };

      const adapter = new OIDCProviderAdapter(config);
      
      await assert.rejects(
        adapter.initialize(),
        (err: any) => err.error === 'invalid_request'
      );
    });
  });

  describe('authorization URL generation', function() {
    let adapter: OIDCProviderAdapter;

    beforeEach(async function() {
      const config = {
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        metadata: minimalMetadata,
        storageHook: mockStorageHook
      };

      adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
    });

    it('should generate valid authorization URL with PKCE', async function() {
      const authUrl = await adapter.generateAuthUrl('test-state', 'https://example.com/callback');
      
      assert(authUrl.includes('response_type=code'), 'Should have response_type=code');
      assert(authUrl.includes('client_id=test-client'), 'Should have client_id');
      assert(authUrl.includes('state=test-state'), 'Should have state');
      assert(authUrl.includes('code_challenge='), 'Should have code_challenge');
      assert(authUrl.includes('code_challenge_method=S256'), 'Should have S256 method');
    });

    it('should store PKCE verifier', async function() {
      await adapter.generateAuthUrl('test-state', 'https://example.com/callback');
      
      const verifier = await mockStorageHook.retrievePKCEState('test-state', 'test-state');
      assert(verifier, 'Should store PKCE verifier');
      assert(typeof verifier === 'string', 'Verifier should be string');
    });

    it('should throw error if not initialized', async function() {
      const uninitializedAdapter = new OIDCProviderAdapter({
        clientId: 'test-client',
        scopes: ['openid'],
        metadata: minimalMetadata
      });

      await assert.rejects(
        uninitializedAdapter.generateAuthUrl('test-state', 'https://example.com/callback'),
        (err: any) => err.error === 'invalid_request'
      );
    });
  });
});
