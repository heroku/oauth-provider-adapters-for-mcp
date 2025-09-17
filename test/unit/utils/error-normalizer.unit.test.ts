/**
 * Error Normalizer unit tests
 * Tests error normalization functionality in isolation
 */

import assert from 'assert';
import { ErrorNormalizer } from '../../../dist/cjs/utils/error-normalizer.js';

describe('ErrorNormalizer', function() {
  describe('normalizeError', function() {
    it('should normalize HTTP errors', function() {
      const httpError = {
        status: 400,
        statusText: 'Bad Request',
        data: { error: 'invalid_request', error_description: 'Invalid client' }
      };
      
      const context = { endpoint: '/token', issuer: 'https://auth.example.com' };
      const result = ErrorNormalizer.normalizeError(httpError, context, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 400);
      assert.equal(result.error, 'invalid_request');
      assert.equal(result.error_description, 'Bad Request');
      assert.equal(result.endpoint, context.endpoint);
      assert.equal(result.issuer, context.issuer);
    });

    it('should normalize network errors', function() {
      const networkError = new Error('Network timeout');
      const context = { endpoint: '/discovery' };
      const result = ErrorNormalizer.normalizeError(networkError, context, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 504);
      assert.equal(result.error, 'temporarily_unavailable');
      assert(result.error_description?.includes('Network timeout'));
      assert.equal(result.endpoint, context.endpoint);
    });

    it('should normalize unknown errors', function() {
      const unknownError = { someProperty: 'value' };
      const context = { endpoint: '/authorize' };
      const result = ErrorNormalizer.normalizeError(unknownError, context, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 500);
      assert.equal(result.error, 'server_error');
      assert.equal(result.error_description, 'Internal Server Error');
      assert.equal(result.endpoint, context.endpoint);
    });

    it('should handle missing context gracefully', function() {
      const error = new Error('Test error');
      const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 500);
      assert.equal(result.error, 'server_error');
    });
  });
});
