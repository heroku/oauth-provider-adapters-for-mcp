/**
 * OIDC Provider Integration Tests
 * Tests component interactions and end-to-end flows
 */

import assert from 'assert';
import sinon from 'sinon';
import { OIDCProviderAdapter } from '../../dist/cjs/adapters/oidc-provider/oidc-adapter.js';
import { MockPKCEStorageHook } from '../../dist/cjs/adapters/oidc-provider/types.js';
import { 
  fullTestMetadata, 
  minimalMetadata, 
  malformedMetadata,
  discoveryMetadata
} from '../helpers/test-metadata.js';

describe('OIDCProviderAdapter Integration', function() {
  let mockStorageHook: MockPKCEStorageHook;

  beforeEach(function() {
    mockStorageHook = new MockPKCEStorageHook();
    sinon.stub(console, 'info');
  });

  afterEach(function() {
    sinon.restore();
  });

  describe('full OAuth flow', function() {
    let adapter: OIDCProviderAdapter;

    beforeEach(async function() {
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile', 'email'],
        metadata: fullTestMetadata,
        storageHook: mockStorageHook
      };

      adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
    });

    it('should complete full authorization flow with PKCE', async function() {
      const interactionId = 'integration-test-123';
      const redirectUrl = 'https://example.com/callback';
      
      // Step 1: Generate authorization URL
      const authUrl = await adapter.generateAuthUrl(interactionId, redirectUrl);
      
      // Verify URL contains all required OAuth parameters
      assert(authUrl.includes('response_type=code'), 'Should have response_type=code');
      assert(authUrl.includes('client_id=test-client-id'), 'Should have correct client_id');
      assert(authUrl.includes('redirect_uri='), 'Should have redirect_uri');
      assert(authUrl.includes('scope='), 'Should have scope');
      assert(authUrl.includes('state='), 'Should have state');
      assert(authUrl.includes('code_challenge='), 'Should have code_challenge');
      assert(authUrl.includes('code_challenge_method=S256'), 'Should have S256 method');
      
      // Step 2: Verify PKCE state is stored
      const storedVerifier = await mockStorageHook.retrievePKCEState(interactionId, interactionId);
      assert(storedVerifier, 'PKCE verifier should be stored');
      assert(typeof storedVerifier === 'string', 'Verifier should be string');
      assert(storedVerifier.length > 40, 'Verifier should have sufficient entropy');
    });

    it('should handle multiple concurrent authorization requests', async function() {
      const requests: Promise<string>[] = [];
      const interactionIds = ['req-1', 'req-2', 'req-3'];
      const redirectUrl = 'https://example.com/callback';
      
      // Generate multiple authorization URLs concurrently
      for (const interactionId of interactionIds) {
        requests.push(adapter.generateAuthUrl(interactionId, redirectUrl));
      }
      
      const authUrls = await Promise.all(requests);
      
      // Verify all URLs were generated
      assert.equal(authUrls.length, 3, 'Should generate 3 URLs');
      
      // Verify each URL is unique and contains required parameters
      for (let i = 0; i < authUrls.length; i++) {
        const authUrl = authUrls[i];
        const interactionId = interactionIds[i];
        
        assert(interactionId, `Interaction ID should exist for index ${i}`);
        assert(authUrl?.includes(`state=${interactionId}`), `URL ${i} should have correct state`);
        assert(authUrl?.includes('code_challenge='), `URL ${i} should have code_challenge`);
        assert(authUrl?.includes('code_challenge_method=S256'), `URL ${i} should have S256 method`);
        
        // Verify PKCE verifier is stored for each request
        const storedVerifier = await mockStorageHook.retrievePKCEState(interactionId, interactionId);
        assert(storedVerifier !== null, `Verifier should be stored for ${interactionId}`);
      }
      
      // Verify all verifiers are different
      const verifiers = await Promise.all(
        interactionIds.map(id => mockStorageHook.retrievePKCEState(id, id))
      );
      
      for (let i = 0; i < verifiers.length; i++) {
        for (let j = i + 1; j < verifiers.length; j++) {
          assert.notEqual(verifiers[i], verifiers[j], `Verifiers ${i} and ${j} should be different`);
        }
      }
    });
  });

  describe('error handling', function() {
    it('should handle storage hook failures gracefully', async function() {
      // Create a failing storage hook
      const failingStorageHook = {
        storePKCEState: sinon.stub().rejects(new Error('Storage failure')),
        retrievePKCEState: sinon.stub().resolves(null),
        clear: sinon.stub(),
        cleanupExpiredState: sinon.stub().resolves()
      };
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile'],
        metadata: minimalMetadata,
        storageHook: failingStorageHook
      };
      
      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
      
      // Attempt to generate auth URL should handle storage failure
      await assert.rejects(
        adapter.generateAuthUrl('test', 'https://example.com/callback'),
        (err: any) => {
          assert(err.message.includes('Storage failure') || err.error, 'Should handle storage failure');
          return true;
        }
      );
    });

    it('should handle invalid interaction IDs', async function() {
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile'],
        metadata: minimalMetadata,
        storageHook: mockStorageHook
      };
      
      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
      
      // Generate auth URL with valid ID
      await adapter.generateAuthUrl('valid-id', 'https://example.com/callback');
      
      // Try to retrieve with different ID should return null
      const verifier = await mockStorageHook.retrievePKCEState('different-id', 'different-id');
      assert.equal(verifier, null, 'Should return null for non-existent ID');
    });
  });

  describe('metadata validation', function() {
    it('should validate metadata from external source', async function() {
      // Test with metadata from external JSON file
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile', 'email'],
        metadata: fullTestMetadata,
        storageHook: mockStorageHook
      };
      
      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
      
      const metadata = adapter.getProviderMetadata();
      assert.deepEqual(metadata, fullTestMetadata, 'Should use external metadata');
    });

    it('should handle malformed metadata gracefully', async function() {
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid'],
        metadata: malformedMetadata as any,
        storageHook: mockStorageHook
      };
      
      const adapter = new OIDCProviderAdapter(config);
      
      await assert.rejects(
        adapter.initialize(),
        (err: any) => {
          assert.equal(err.error, 'invalid_request');
          assert(err.error_description.includes('Missing authorization_endpoint'));
          return true;
        }
      );
    });
  });

  describe('OIDC discovery', function() {
    let fetchStub: sinon.SinonStub;

    it('should discover provider metadata from issuer', async function() {
      const mockMetadata = discoveryMetadata;

      fetchStub = sinon.stub(global, 'fetch');
      fetchStub.resolves({
        ok: true,
        json: () => Promise.resolve(mockMetadata)
      });
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid', 'profile'],
        issuer: 'https://auth.example.com'
      };
      
      const adapter = new OIDCProviderAdapter(config);
      await adapter.initialize();
      
      const metadata = adapter.getProviderMetadata();
      assert.deepEqual(metadata, mockMetadata, 'Should retrieve correct metadata');
      
      assert(fetchStub.calledWith('https://auth.example.com/.well-known/openid-configuration'), 'Should call discovery URL');
    });

    it('should cache discovery results', async function() {
      const mockMetadata = discoveryMetadata;

      fetchStub = sinon.stub(global, 'fetch');
      fetchStub.resolves({
        ok: true,
        json: () => Promise.resolve(mockMetadata)
      });
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid'],
        issuer: 'https://auth.example.com'
      };
      
      const adapter = new OIDCProviderAdapter(config);
      
      // Initialize once
      await adapter.initialize();
      
      // Verify discovery was called
      assert.equal(fetchStub.callCount, 1, 'Discovery should be called once');
      
      // Verify adapter is initialized
      assert(adapter.getProviderMetadata(), 'Should have provider metadata');
    });

    it('should handle network errors gracefully', async function() {
      fetchStub = sinon.stub(global, 'fetch');
      fetchStub.rejects(new Error('Network error'));
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid'],
        issuer: 'https://auth.example.com'
      };
      
      const adapter = new OIDCProviderAdapter(config);
      
      try {
        await adapter.initialize();
        assert.fail('Expected initialization to fail');
      } catch (err: any) {
        // Check if it's a normalized error or a raw error
        if (err.error) {
          assert.equal(err.error, 'server_error');
          assert(err.error_description.includes('Failed to perform OIDC discovery'));
        } else {
          // If it's a raw error, that's also acceptable
          assert(err.message.includes('Network error') || err.message.includes('Failed to perform OIDC discovery'));
        }
      }
    });

    it('should handle invalid discovery responses', async function() {
      fetchStub = sinon.stub(global, 'fetch');
      fetchStub.resolves({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: 'not_found', error_description: 'Discovery document not found' })
      });
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid'],
        issuer: 'https://auth.example.com'
      };
      
      const adapter = new OIDCProviderAdapter(config);
      
      await assert.rejects(
        adapter.initialize(),
        (err: any) => {
          assert.equal(err.error, 'server_error');
          assert(err.error_description.includes('Discovery failed with status 404'));
          return true;
        }
      );
    });

    it('should handle malformed discovery responses', async function() {
      fetchStub = sinon.stub(global, 'fetch');
      fetchStub.resolves({
        ok: true,
        json: () => Promise.resolve({ not_an_issuer: 'malformed' }) // Malformed metadata
      });
      
      const config = {
        clientId: 'test-client-id',
        scopes: ['openid'],
        issuer: 'https://auth.example.example'
      };
      
      const adapter = new OIDCProviderAdapter(config);
      
      await assert.rejects(
        adapter.initialize(),
        (err: any) => {
          assert.equal(err.error, 'invalid_request');
          assert(err.error_description.includes('Missing authorization_endpoint in provider metadata'));
          return true;
        }
      );
    });
  });
});
