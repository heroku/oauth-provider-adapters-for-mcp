/**
 * Config validation unit tests
 * Tests Zod schema validation for the specific requirements:
 * - issuer vs serverMetadata exclusivity/requirements
 * - clientId/clientSecret validation
 * - scopes format and defaults
 * - timeouts shape
 * - customParameters passthrough
 * Co-located with config.ts for better maintainability
 */

import { expect } from 'chai';
import { validate, safeValidate } from './config.js';
import {
  createOIDCConfig,
  createOIDCConfigWithMetadata,
  createOIDCConfigWithSecret,
  createOIDCConfigWithTimeouts,
  createOIDCConfigWithParams,
  createOIDCConfigMinimal,
  createInvalidOIDCConfig,
} from '../../fixtures/test-data.js';

describe('OIDCProviderConfig Validation', function () {
  describe('issuer vs serverMetadata exclusivity/requirements', function () {
    it('should validate valid configuration with issuer', function () {
      const validConfig = createOIDCConfig();

      const result = validate(validConfig);
      expect(result).to.deep.equal(validConfig);
    });

    it('should validate valid configuration with serverMetadata', function () {
      const validConfig = createOIDCConfigWithMetadata();

      const result = validate(validConfig);
      expect(result).to.deep.equal(validConfig);
    });

    it('should throw ZodError for both issuer and serverMetadata', function () {
      const invalidConfig = createInvalidOIDCConfig('both-issuer-metadata');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].message).to.include('Provide exactly one of');
      }
    });

    it('should throw ZodError for neither issuer nor serverMetadata', function () {
      const invalidConfig = {
        clientId: 'test-client-id',
        scopes: ['openid'],
      };

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].message).to.include('Provide exactly one of');
      }
    });

    it('should throw ZodError for invalid issuer URL', function () {
      const invalidConfig = createInvalidOIDCConfig('invalid-issuer');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].path).to.include('issuer');
        expect(error.issues[0].message).to.include('Invalid issuer URL');
      }
    });

    it('should throw ZodError for malformed serverMetadata', function () {
      const invalidConfig = createInvalidOIDCConfig('malformed-metadata');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].path).to.include('authorization_endpoint');
      }
    });
  });

  describe('clientId/clientSecret validation', function () {
    it('should throw ZodError for missing clientId', function () {
      const invalidConfig = createInvalidOIDCConfig('missing-client-id');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].path).to.include('clientId');
        expect(error.issues[0].message).to.include(
          'expected string, received undefined'
        );
      }
    });

    it('should throw ZodError for empty clientId', function () {
      const invalidConfig = createInvalidOIDCConfig('empty-client-id');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].path).to.include('clientId');
        expect(error.issues[0].message).to.include('clientId is required');
      }
    });

    it('should validate optional clientSecret', function () {
      const validConfig = createOIDCConfigWithSecret({ scopes: ['openid'] });

      const result = validate(validConfig);
      expect(result.clientSecret).to.equal('test-client-secret');
    });

    it('should validate missing clientSecret (public client)', function () {
      const validConfig = createOIDCConfigMinimal();

      const result = validate(validConfig);
      expect(result.clientSecret).to.be.undefined;
    });
  });

  describe('scopes format and defaults', function () {
    it('should validate default scopes', function () {
      const configWithoutScopes = createOIDCConfig();

      const result = validate(configWithoutScopes);
      expect(result.scopes).to.deep.equal(['openid', 'profile', 'email']);
    });

    it('should validate custom scopes', function () {
      const configWithCustomScopes = createOIDCConfig({
        scopes: ['openid', 'custom_scope'],
      });

      const result = validate(configWithCustomScopes);
      expect(result.scopes).to.deep.equal(['openid', 'custom_scope']);
    });

    it('should validate empty scopes array', function () {
      const configWithEmptyScopes = createOIDCConfig({ scopes: [] });

      const result = validate(configWithEmptyScopes);
      expect(result.scopes).to.deep.equal([]);
    });
  });

  describe('timeouts shape', function () {
    it('should validate timeouts configuration', function () {
      const validConfig = createOIDCConfigWithTimeouts({ scopes: ['openid'] });

      const result = validate(validConfig);
      expect(result.timeouts).to.deep.equal({
        connect: 5000,
        response: 10000,
      });
    });

    it('should validate partial timeouts configuration', function () {
      const validConfig = createOIDCConfig({
        scopes: ['openid'],
        timeouts: { connect: 3000 },
      });

      const result = validate(validConfig);
      expect(result.timeouts).to.deep.equal({
        connect: 3000,
      });
    });

    it('should throw ZodError for invalid timeout values', function () {
      const invalidConfig = createInvalidOIDCConfig('invalid-timeout');

      try {
        validate(invalidConfig);
        expect.fail('Expected to throw');
      } catch (error: any) {
        expect(error).to.have.property('name', 'ZodError');
        expect(error.issues[0].path).to.include('timeouts', 'connect');
        expect(error.issues[0].message).to.include('positive integer');
      }
    });
  });

  describe('customParameters passthrough', function () {
    it('should validate customParameters', function () {
      const validConfig = createOIDCConfigWithParams({
        scopes: ['openid'],
        customParameters: {
          prompt: 'select_account',
          access_type: 'offline',
        },
      });

      const result = validate(validConfig);
      expect(result.customParameters).to.deep.equal({
        prompt: 'select_account',
        access_type: 'offline',
      });
    });

    it('should validate empty customParameters', function () {
      const validConfig = createOIDCConfig({
        scopes: ['openid'],
        customParameters: {},
      });

      const result = validate(validConfig);
      expect(result.customParameters).to.deep.equal({});
    });

    it('should validate missing customParameters', function () {
      const validConfig = createOIDCConfigMinimal();

      const result = validate(validConfig);
      expect(result.customParameters).to.be.undefined;
    });
  });

  describe('safeValidate() function', function () {
    it('should return success for valid configuration', function () {
      const validConfig = createOIDCConfigMinimal();

      const result = safeValidate(validConfig);
      expect(result.success).to.be.true;
      expect(result.data).to.deep.equal(validConfig);
      expect(result.error).to.be.undefined;
    });

    it('should return error for invalid configuration', function () {
      const invalidConfig = createInvalidOIDCConfig('empty-client-id');

      const result = safeValidate(invalidConfig);
      expect(result.success).to.be.false;
      expect(result.data).to.be.undefined;
      expect(result.error).to.have.property('name', 'ZodError');
    });
  });
});
