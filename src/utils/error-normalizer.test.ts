/**
 * Error Normalizer unit tests
 * Tests error normalization functionality in isolation
 * Co-located with the utility for better maintainability
 */

import { expect } from 'chai';
import assert from 'assert';
import { ErrorNormalizer } from './error-normalizer.js';
import { errorData, contextData } from '../fixtures/test-data.js';

describe('ErrorNormalizer', () => {
  const defaultIssuer = 'https://issuer.example.com';

  it('passes through OAuth-shaped errors', () => {
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

    expect(normalized.statusCode).to.equal(400);
    expect(normalized.error).to.equal('invalid_request');
    expect(normalized.error_description).to.equal('Missing parameter');
    expect(normalized.endpoint).to.equal('/token');
    expect(normalized.issuer).to.equal(defaultIssuer);
  });

  it('normalizes fetch-like response objects', () => {
    const input = { status: 404, statusText: 'Not Found' } as const;
    const normalized = ErrorNormalizer.normalizeError(
      input,
      { endpoint: '/authorize' },
      defaultIssuer
    );

    expect(normalized.statusCode).to.equal(404);
    expect(normalized.error).to.equal('invalid_request');
    expect(normalized.error_description).to.equal('Not Found');
    expect(normalized.endpoint).to.equal('/authorize');
    expect(normalized.issuer).to.equal(defaultIssuer);
  });

  it('falls back to message when error_description is missing on OAuth-shaped input', () => {
    const input = {
      statusCode: 400,
      error: 'invalid_request',
      message: 'Bad input',
    };
    const normalized = ErrorNormalizer.normalizeError(input, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(400);
    expect(normalized.error).to.equal('invalid_request');
    expect(normalized.error_description).to.equal('Bad input');
  });

  it('maps native timeout errors to temporarily_unavailable (504)', () => {
    const input = new Error('Request timeout after 30s');
    const normalized = ErrorNormalizer.normalizeError(input, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(504);
    expect(normalized.error).to.equal('temporarily_unavailable');
    expect(normalized.error_description).to.include('timeout');
    expect(normalized.issuer).to.equal(defaultIssuer);
  });

  it('maps native network errors to server_error (503)', () => {
    const input = new Error('ECONNREFUSED 127.0.0.1');
    const normalized = ErrorNormalizer.normalizeError(input, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(503);
    expect(normalized.error).to.equal('server_error');
  });

  it('maps unauthorized errors to unauthorized (401)', () => {
    const input = new Error('Unauthorized request 401');
    const normalized = ErrorNormalizer.normalizeError(input, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(401);
    expect(normalized.error).to.equal('unauthorized');
  });

  it('maps forbidden errors to access_denied (403)', () => {
    const input = new Error('Forbidden resource 403');
    const normalized = ErrorNormalizer.normalizeError(input, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(403);
    expect(normalized.error).to.equal('access_denied');
  });

  it('normalizes string primitives to server_error (500)', () => {
    const normalized = ErrorNormalizer.normalizeError(
      'just failed',
      { issuer: 'x' },
      defaultIssuer
    );
    expect(normalized.statusCode).to.equal(500);
    expect(normalized.error).to.equal('server_error');
    expect(normalized.error_description).to.equal('just failed');
    expect(normalized.issuer).to.equal('x');
  });

  it('creates fallback error for unrecognized shapes', () => {
    const normalized = ErrorNormalizer.normalizeError({}, {}, defaultIssuer);
    expect(normalized.statusCode).to.equal(500);
    expect(normalized.error).to.equal('server_error');
    expect(normalized.error_description).to.match(
      /Internal Server Error|HTTP 500/i
    );
  });

  it('uses HTTP reason phrase when statusText missing', () => {
    const normalized = ErrorNormalizer.normalizeError(
      { status: 418 },
      {},
      defaultIssuer
    );
    expect(normalized.statusCode).to.equal(418);
    expect(normalized.error).to.equal('invalid_request');
    expect(normalized.error_description).to.equal('HTTP 418');
  });

  describe('mapStatusToOAuthError coverage', () => {
    const ctx = {};

    it('maps error codes to OAuth error codes', () => {
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
        expect(n.error).to.equal(oauthCodes[index]);
      });
    });

    it('maps 500/502/503/504/>500/<400 -> server_error', () => {
      [500, 502, 503, 504, 550, 200].forEach((code) => {
        const n = ErrorNormalizer.normalizeError(
          { status: code },
          ctx,
          defaultIssuer
        );
        expect(n.error).to.equal('server_error');
      });
    });

    it('default: 400-499, < -> invalid_request', () => {
      const n = ErrorNormalizer.normalizeError(
        { status: 456 },
        ctx,
        defaultIssuer
      );
      expect(n.error).to.equal('invalid_request');
    });
  });

  // Additional test coverage from newer tests
  describe('Additional test coverage', function () {
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
