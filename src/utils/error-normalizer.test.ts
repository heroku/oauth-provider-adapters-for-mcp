/**
 * Error Normalizer unit tests
 * Tests error normalization functionality in isolation
 * Co-located with the utility for better maintainability
 */

import assert from 'assert';
import { ErrorNormalizer } from './error-normalizer.js';
import { errorData, contextData } from '../fixtures/test-data.js';

describe('ErrorNormalizer', function () {
  const defaultIssuer = 'https://issuer.example.com';

  describe('normalizeError', function () {
    it('should pass through OAuth-shaped errors', function () {
      const input = {
        statusCode: 400,
        error: 'invalid_request',
        error_description: 'Missing parameter',
      };

      const normalized = ErrorNormalizer.normalizeError(
        input,
        { endpoint: '/token' },
        defaultIssuer
      );

      assert.equal(normalized.statusCode, 400);
      assert.equal(normalized.error, 'invalid_request');
      assert.equal(normalized.error_description, 'Missing parameter');
      assert.equal(normalized.endpoint, '/token');
      assert.equal(normalized.issuer, defaultIssuer);
    });

    it('should normalize fetch-like response objects', function () {
      const input = { status: 404, statusText: 'Not Found' } as const;
      const normalized = ErrorNormalizer.normalizeError(
        input,
        { endpoint: '/authorize' },
        defaultIssuer
      );

      assert.equal(normalized.statusCode, 404);
      assert.equal(normalized.error, 'invalid_request');
      assert.equal(normalized.error_description, 'Not Found');
      assert.equal(normalized.endpoint, '/authorize');
      assert.equal(normalized.issuer, defaultIssuer);
    });

    it('should fall back to message when error_description is missing on OAuth-shaped input', function () {
      const input = {
        statusCode: 400,
        error: 'invalid_request',
        message: 'Bad input',
      };
      const normalized = ErrorNormalizer.normalizeError(
        input,
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 400);
      assert.equal(normalized.error, 'invalid_request');
      assert.equal(normalized.error_description, 'Bad input');
    });

    it('should map native timeout errors to temporarily_unavailable (504)', function () {
      const input = new Error('Request timeout after 30s');
      const normalized = ErrorNormalizer.normalizeError(
        input,
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 504);
      assert.equal(normalized.error, 'temporarily_unavailable');
      assert(normalized.error_description?.includes('timeout'));
      assert.equal(normalized.issuer, defaultIssuer);
    });

    it('should map native network errors to server_error (503)', function () {
      const input = new Error('ECONNREFUSED 127.0.0.1');
      const normalized = ErrorNormalizer.normalizeError(
        input,
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 503);
      assert.equal(normalized.error, 'server_error');
    });

    it('should map unauthorized errors to unauthorized (401)', function () {
      const input = new Error('Unauthorized request 401');
      const normalized = ErrorNormalizer.normalizeError(
        input,
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 401);
      assert.equal(normalized.error, 'unauthorized');
    });

    it('should map forbidden errors to access_denied (403)', function () {
      const input = new Error('Forbidden resource 403');
      const normalized = ErrorNormalizer.normalizeError(
        input,
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 403);
      assert.equal(normalized.error, 'access_denied');
    });

    it('should normalize string primitives to server_error (500)', function () {
      const normalized = ErrorNormalizer.normalizeError(
        'just failed',
        { issuer: 'x' },
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 500);
      assert.equal(normalized.error, 'server_error');
      assert.equal(normalized.error_description, 'just failed');
      assert.equal(normalized.issuer, 'x');
    });

    it('should create fallback error for unrecognized shapes', function () {
      const normalized = ErrorNormalizer.normalizeError({}, {}, defaultIssuer);
      assert.equal(normalized.statusCode, 500);
      assert.equal(normalized.error, 'server_error');
      assert(
        normalized.error_description?.match(/Internal Server Error|HTTP 500/i)
      );
    });

    it('should use HTTP reason phrase when statusText missing', function () {
      const normalized = ErrorNormalizer.normalizeError(
        { status: 418 },
        {},
        defaultIssuer
      );
      assert.equal(normalized.statusCode, 418);
      assert.equal(normalized.error, 'invalid_request');
      assert.equal(normalized.error_description, 'HTTP 418');
    });

    it('should handle missing context gracefully', function () {
      const error = new Error('Test error');
      const result = ErrorNormalizer.normalizeError(
        error,
        {},
        'https://auth.example.com'
      );

      assert.equal(result.statusCode, 500);
      assert.equal(result.error, 'server_error');
    });
  });

  describe('mapStatusToOAuthError coverage', function () {
    const ctx = {};

    it('should map error codes to OAuth error codes', function () {
      const codes = [400, 401, 403, 429];
      const oauthCodes = [
        'invalid_request',
        'unauthorized',
        'access_denied',
        'temporarily_unavailable',
      ];

      codes.forEach((code, index) => {
        const n = ErrorNormalizer.normalizeError(
          { status: code },
          ctx,
          defaultIssuer
        );
        assert.equal(n.error, oauthCodes[index]);
      });
    });

    it('should map 500/502/503/504/>500/<400 -> server_error', function () {
      [500, 502, 503, 504, 550, 200].forEach((code) => {
        const n = ErrorNormalizer.normalizeError(
          { status: code },
          ctx,
          defaultIssuer
        );
        assert.equal(n.error, 'server_error');
      });
    });

    it('should default: 400-499, < -> invalid_request', function () {
      const n = ErrorNormalizer.normalizeError(
        { status: 456 },
        ctx,
        defaultIssuer
      );
      assert.equal(n.error, 'invalid_request');
    });
  });

  describe('Legacy test coverage', function () {
    it('should normalize HTTP errors from fixtures', function () {
      const httpError = errorData.http400;
      const context = contextData.tokenEndpoint;
      const result = ErrorNormalizer.normalizeError(
        httpError,
        context,
        'https://auth.example.com'
      );

      assert.equal(result.statusCode, 400);
      assert.equal(result.error, 'invalid_request');
      assert.equal(result.error_description, 'Bad Request');
      assert.equal(result.endpoint, context.endpoint);
      assert.equal(result.issuer, context.issuer);
    });

    it('should normalize network errors from fixtures', function () {
      const networkError = errorData.networkTimeout;
      const context = contextData.discoveryEndpoint;
      const result = ErrorNormalizer.normalizeError(
        networkError,
        context,
        'https://auth.example.com'
      );

      assert.equal(result.statusCode, 504);
      assert.equal(result.error, 'temporarily_unavailable');
      assert(result.error_description?.includes('Network timeout'));
      assert.equal(result.endpoint, context.endpoint);
    });

    it('should normalize unknown errors from fixtures', function () {
      const unknownError = { someProperty: 'value', anotherProperty: 123 };
      const context = contextData.authorizeEndpoint;
      const result = ErrorNormalizer.normalizeError(
        unknownError,
        context,
        'https://auth.example.com'
      );

      assert.equal(result.statusCode, 500);
      assert.equal(result.error, 'server_error');
      assert.equal(result.error_description, 'Internal Server Error');
      assert.equal(result.endpoint, context.endpoint);
    });
  });
});
