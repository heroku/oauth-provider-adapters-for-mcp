/**
 * Tests for fromEnvironment helper
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { resolve, join } from 'path';
import { writeFileSync, unlinkSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import type { EnvironmentVariables } from './types.js';
import { fromEnvironment } from './from-environment.js';
import { OIDCProviderAdapter } from './oidc-adapter.js';

describe('fromEnvironment', () => {
  describe('fromEnvironment (sync)', () => {
    it('should create adapter with required environment variables', () => {
      const env: EnvironmentVariables = {
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
      const env: EnvironmentVariables = {
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
      const env: EnvironmentVariables = {
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
      const env: EnvironmentVariables = {
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
      const env: EnvironmentVariables = {
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
  });

  describe('Static Metadata Support', () => {
    const testMetadataPath = resolve(
      process.cwd(),
      'src/fixtures/test-oidc-metadata.json'
    );

    it('should create adapter with static metadata from file', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: testMetadataPath,
      };

      const adapter = fromEnvironment({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      expect(adapter.providerName).to.equal('oidc-provider');
    });

    it('should prefer static metadata over issuer URL when both provided', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com', // This should be ignored
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: testMetadataPath, // This takes precedence
      };

      const adapter = fromEnvironment({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      // The adapter should be configured with metadata, not issuer
    });

    it('should throw error when metadata file does not exist', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: '/nonexistent/path/metadata.json',
      };

      expect(() => fromEnvironment({ env })).to.throw(
        /Failed to load IDENTITY_SERVER_METADATA_FILE/
      );
    });

    it('should throw error when metadata file contains invalid JSON', () => {
      // Create a temporary file with invalid JSON
      const tmpDir = mkdtempSync(join(tmpdir(), 'oidc-test-'));
      const invalidJsonPath = join(tmpDir, 'invalid.json');
      writeFileSync(invalidJsonPath, '{ this is not valid json }', 'utf-8');

      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: invalidJsonPath,
      };

      try {
        expect(() => fromEnvironment({ env })).to.throw(
          /Failed to load IDENTITY_SERVER_METADATA_FILE/
        );
      } finally {
        // Clean up
        unlinkSync(invalidJsonPath);
      }
    });

    it('should work with static metadata containing minimal required fields', () => {
      // Create a minimal metadata file
      const tmpDir = mkdtempSync(join(tmpdir(), 'oidc-test-'));
      const minimalMetadataPath = join(tmpDir, 'minimal.json');
      const minimalMetadata = {
        issuer: 'https://minimal.example.com',
        authorization_endpoint: 'https://minimal.example.com/oauth/authorize',
        token_endpoint: 'https://minimal.example.com/oauth/token',
        jwks_uri: 'https://minimal.example.com/.well-known/jwks.json',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      };
      writeFileSync(
        minimalMetadataPath,
        JSON.stringify(minimalMetadata),
        'utf-8'
      );

      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: minimalMetadataPath,
      };

      try {
        const adapter = fromEnvironment({ env });
        expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
      } finally {
        // Clean up
        unlinkSync(minimalMetadataPath);
      }
    });

    it('should load static metadata with custom scopes from file', () => {
      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: testMetadataPath,
        IDENTITY_SCOPE: 'openid profile custom-scope',
      };

      const adapter = fromEnvironment({ env });

      expect(adapter).to.be.instanceOf(OIDCProviderAdapter);
    });

    it('should provide helpful error message for file read errors', () => {
      // Use a path that exists but isn't readable (or doesn't exist)
      const unreadablePath = '/root/secret/metadata.json';

      const env: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: unreadablePath,
      };

      try {
        fromEnvironment({ env });
        expect.fail('Should have thrown an error');
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        const err = error as Error;
        expect(err.message).to.include(
          'Failed to load IDENTITY_SERVER_METADATA_FILE'
        );
        expect(err.message).to.include(unreadablePath);
      }
    });

    it('should work with absolute and relative metadata file paths', () => {
      // Test with absolute path (already tested above, but making it explicit)
      const absolutePathEnv: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: testMetadataPath,
      };

      const adapter1 = fromEnvironment({ env: absolutePathEnv });
      expect(adapter1).to.be.instanceOf(OIDCProviderAdapter);

      // Test with relative path
      const relativePathEnv: EnvironmentVariables = {
        IDENTITY_CLIENT_ID: 'test-client-id',
        IDENTITY_CLIENT_SECRET: 'test-client-secret',
        IDENTITY_SERVER_URL: 'https://auth.example.com',
        IDENTITY_REDIRECT_URI: 'https://app.example.com/callback',
        IDENTITY_SERVER_METADATA_FILE: 'src/fixtures/test-oidc-metadata.json',
      };

      const adapter2 = fromEnvironment({ env: relativePathEnv });
      expect(adapter2).to.be.instanceOf(OIDCProviderAdapter);
    });
  });
});
