/**
 * Error Normalizer unit tests
 * Tests error normalization functionality in isolation
 * Co-located with the utility for better maintainability
 */

import assert from 'assert';
import { ErrorNormalizer } from './error-normalizer.js';
import {
  errorData,
  contextData
} from '../fixtures/test-data.js';

describe('ErrorNormalizer', function() {
  describe('normalizeError', function() {
    it('should normalize HTTP errors', function() {
      const httpError = errorData.http400;
      const context = contextData.tokenEndpoint;
      const result = ErrorNormalizer.normalizeError(httpError, context, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 400);
      assert.equal(result.error, 'invalid_request');
      assert.equal(result.error_description, 'Bad Request');
      assert.equal(result.endpoint, context.endpoint);
      assert.equal(result.issuer, context.issuer);
    });

    it('should normalize network errors', function() {
      const networkError = errorData.networkTimeout;
      const context = contextData.discoveryEndpoint;
      const result = ErrorNormalizer.normalizeError(networkError, context, 'https://auth.example.com');
      
      assert.equal(result.statusCode, 504);
      assert.equal(result.error, 'temporarily_unavailable');
      assert(result.error_description?.includes('Network timeout'));
      assert.equal(result.endpoint, context.endpoint);
    });

    it('should normalize unknown errors', function() {
      const unknownError = { someProperty: 'value', anotherProperty: 123 };
      const context = contextData.authorizeEndpoint;
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

  describe('Missing Branch Coverage', function() {
    describe('getOAuthErrorCode default case branches', function() {
      it('should map 500+ status codes to server_error', function() {
        // Test: statusCode >= 500 -> 'server_error'
        const error = { 
          response: { 
            status: 503, 
            statusText: 'Service Unavailable',
            data: {}
          } 
        };
        const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
        assert.equal(result.error, 'server_error');
        assert.equal(result.statusCode, 503);
      });

      it('should map 400-499 status codes to invalid_request', function() {
        // Test: statusCode >= 400 && < 500 -> 'invalid_request'  
        const error = { 
          response: { 
            status: 422, 
            statusText: 'Unprocessable Entity',
            data: {}
          } 
        };
        const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
        assert.equal(result.error, 'invalid_request');
        assert.equal(result.statusCode, 422);
      });

      it('should map < 400 status codes to server_error', function() {
        // Test: statusCode < 400 -> 'server_error' (coerced to 500 by buildError)
        const error = { 
          response: { 
            status: 200, 
            statusText: 'OK',
            data: {}
          } 
        };
        const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
        assert.equal(result.error, 'server_error');
        assert.equal(result.statusCode, 500); // buildError coerces non-4xx/5xx to 500
      });
    });

    describe('getReasonPhrase fallback logic', function() {
      it('should handle unknown status codes with fallback format', function() {
        // Test: reasonPhrases[statusCode] || `HTTP ${statusCode}`
        // Use an error without statusText to trigger the fallback
        const error = { 
          response: { 
            status: 418, 
            data: {}
          } 
        };
        const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
        assert(result.error_description?.includes('HTTP 418'));
        assert.equal(result.statusCode, 418);
      });
    });

    describe('specific HTTP status code mappings', function() {
      it('should map specific HTTP status codes to correct OAuth errors', function() {
        // Test specific status codes that are missing coverage
        const testCases = [
          { status: 401, expectedError: 'unauthorized' },
          { status: 403, expectedError: 'access_denied' },
          { status: 404, expectedError: 'invalid_request' },
          { status: 429, expectedError: 'temporarily_unavailable' }
        ];

        testCases.forEach(({ status, expectedError }) => {
          const error = { 
            response: { 
              status, 
              statusText: 'Test',
              data: {}
            } 
          };
          const result = ErrorNormalizer.normalizeError(error, {}, 'https://auth.example.com');
          assert.equal(result.error, expectedError, `Status ${status} should map to ${expectedError}`);
          assert.equal(result.statusCode, status);
        });
      });
    });
  });
});
