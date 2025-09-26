/**
 * Token Exchange Service unit tests
 * Tests token exchange functionality in isolation
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { TokenExchangeService } from './token-exchange.js';
import { oidcMetadata } from '../../fixtures/test-data.js';
import { setupSinonStubs } from '../../testUtils/testHelpers.js';

describe('TokenExchangeService', function () {
  let restoreStubs: () => void;
  let service: TokenExchangeService;
  let fetchStub: sinon.SinonStub;
  let loggerStub: any;
  let createStandardErrorStub: sinon.SinonStub;
  let normalizeErrorStub: sinon.SinonStub;

  const mockConfig = {
    clientId: 'test-client-id',
    scopes: ['openid', 'profile', 'email'],
    clientSecret: undefined,
    customParameters: {},
  };

  const mockMetadata = oidcMetadata.minimal;

  beforeEach(function () {
    restoreStubs = setupSinonStubs();
    fetchStub = sinon.stub(global, 'fetch');

    loggerStub = {
      info: sinon.stub(),
      error: sinon.stub(),
    };

    createStandardErrorStub = sinon
      .stub()
      .callsFake((error, message, context) => {
        const err = new Error(message) as any;
        err.error = error;
        err.error_description = message;
        Object.assign(err, context);
        return err;
      });

    normalizeErrorStub = sinon.stub().callsFake((error, context) => {
      const err = new Error('Normalized error') as any;
      err.error = 'server_error';
      err.error_description =
        error instanceof Error ? error.message : String(error);
      Object.assign(err, context);
      return err;
    });

    service = new TokenExchangeService(
      mockConfig as any,
      mockMetadata as any,
      loggerStub,
      createStandardErrorStub,
      normalizeErrorStub
    );
  });

  afterEach(function () {
    restoreStubs();
    fetchStub.restore();
  });

  describe('exchangeCode', function () {
    it('should exchange authorization code for tokens successfully', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        id_token: 'test-id-token',
        expires_in: 3600,
        scope: 'openid profile email',
        token_type: 'Bearer',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.accessToken).to.equal('test-access-token');
      expect(result.refreshToken).to.equal('test-refresh-token');
      expect(result.idToken).to.equal('test-id-token');
      expect(result.expiresIn).to.equal(3600);
      expect(result.scope).to.equal('openid profile email');
      expect(result.userData).to.deep.equal({ token_type: 'Bearer' });

      // Verify fetch was called with correct parameters
      expect(fetchStub.callCount).to.equal(1);
      const [url, options] = fetchStub.firstCall.args;
      expect(url).to.equal('https://auth.example.com/oauth/token');
      expect(options.method).to.equal('POST');
      expect(options.headers['Content-Type']).to.equal(
        'application/x-www-form-urlencoded'
      );

      const body = new URLSearchParams(options.body);
      expect(body.get('grant_type')).to.equal('authorization_code');
      expect(body.get('code')).to.equal('test-code');
      expect(body.get('code_verifier')).to.equal('test-verifier');
      expect(body.get('redirect_uri')).to.equal('https://example.com/callback');
      expect(body.get('client_id')).to.equal('test-client-id');
    });

    it('should handle token response without optional fields', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.accessToken).to.equal('test-access-token');
      expect(result.refreshToken).to.be.undefined;
      expect(result.idToken).to.be.undefined;
      expect(result.expiresIn).to.be.undefined;
      expect(result.userData).to.be.undefined;
    });

    it('should handle comma-delimited scopes', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
        scope: 'openid,profile,email',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.scope).to.equal('openid profile email');
    });

    it('should fallback to configured scopes when provider response has none', async function () {
      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.scope).to.equal('openid profile email');
    });

    it('should send client credentials via Basic auth when client_secret provided', async function () {
      const configWithSecret = {
        ...mockConfig,
        clientSecret: 'test-client-secret',
      };

      const serviceWithSecret = new TokenExchangeService(
        configWithSecret as any,
        mockMetadata as any,
        loggerStub,
        createStandardErrorStub,
        normalizeErrorStub
      );

      const mockTokenResponse = {
        access_token: 'test-access-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      await serviceWithSecret.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      const [, options] = fetchStub.firstCall.args;
      expect(options.headers.Authorization).to.match(/^Basic\s+/);
      const body = new URLSearchParams(options.body);
      expect(body.get('client_secret')).to.be.null;
    });

    it('should handle OAuth error responses', async function () {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The authorization code has expired',
      };

      fetchStub.resolves({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: sinon.stub().resolves(errorResponse),
      });

      try {
        await service.exchangeCode(
          'expired-code',
          'test-verifier',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch {
        expect(createStandardErrorStub.calledOnce).to.be.true;
        expect(createStandardErrorStub.firstCall.args[0]).to.equal(
          'invalid_grant'
        );
        expect(createStandardErrorStub.firstCall.args[1]).to.equal(
          'The authorization code has expired'
        );
      }
    });

    it('should handle network errors', async function () {
      fetchStub.rejects(new Error('Network error'));

      try {
        await service.exchangeCode(
          'test-code',
          'test-verifier',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch {
        expect(normalizeErrorStub.calledOnce).to.be.true;
      }
    });

    it('should throw error for missing access_token in response', async function () {
      const mockTokenResponse = {
        refresh_token: 'test-refresh-token',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      try {
        await service.exchangeCode(
          'test-code',
          'test-verifier',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch {
        expect(createStandardErrorStub.calledOnce).to.be.true;
        expect(createStandardErrorStub.firstCall.args[0]).to.equal(
          'server_error'
        );
        expect(createStandardErrorStub.firstCall.args[1]).to.equal(
          'Missing access_token in provider response'
        );
      }
    });

    it('should handle invalid JSON response', async function () {
      fetchStub.resolves({
        ok: true,
        json: sinon.stub().rejects(new Error('Invalid JSON')),
      });

      try {
        await service.exchangeCode(
          'test-code',
          'test-verifier',
          'https://example.com/callback'
        );
        expect.fail('Expected to throw');
      } catch {
        expect(createStandardErrorStub.calledOnce).to.be.true;
        expect(createStandardErrorStub.firstCall.args[0]).to.equal(
          'server_error'
        );
        expect(createStandardErrorStub.firstCall.args[1]).to.equal(
          'Invalid JSON response from token endpoint'
        );
      }
    });
  });

  describe('refreshToken', function () {
    it('should refresh token successfully', async function () {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        scope: 'openid profile',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.refreshToken('old-refresh-token');

      expect(result.accessToken).to.equal('new-access-token');
      expect(result.refreshToken).to.equal('new-refresh-token');
      expect(result.expiresIn).to.equal(3600);
      expect(result.scope).to.equal('openid profile');

      // Verify fetch was called with correct parameters
      expect(fetchStub.callCount).to.equal(1);
      const [url, options] = fetchStub.firstCall.args;
      expect(url).to.equal('https://auth.example.com/oauth/token');

      const body = new URLSearchParams(options.body);
      expect(body.get('grant_type')).to.equal('refresh_token');
      expect(body.get('refresh_token')).to.equal('old-refresh-token');
      expect(body.get('client_id')).to.equal('test-client-id');
    });

    it('should handle refresh without new refresh token', async function () {
      const mockTokenResponse = {
        access_token: 'new-access-token',
        expires_in: 3600,
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.refreshToken('old-refresh-token');

      expect(result.accessToken).to.equal('new-access-token');
      expect(result.refreshToken).to.be.undefined;
      expect(result.expiresIn).to.equal(3600);
    });

    it('should handle invalid_grant error for expired refresh token', async function () {
      const errorResponse = {
        error: 'invalid_grant',
        error_description: 'The refresh token has expired',
      };

      fetchStub.resolves({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: sinon.stub().resolves(errorResponse),
      });

      try {
        await service.refreshToken('expired-refresh-token');
        expect.fail('Expected to throw');
      } catch {
        expect(createStandardErrorStub.calledOnce).to.be.true;
        expect(createStandardErrorStub.firstCall.args[0]).to.equal(
          'invalid_grant'
        );
        expect(createStandardErrorStub.firstCall.args[1]).to.equal(
          'The refresh token has expired'
        );
      }
    });

    it('should handle unauthorized client error', async function () {
      const errorResponse = {
        error: 'invalid_client',
        error_description: 'Client authentication failed',
      };

      fetchStub.resolves({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: sinon.stub().resolves(errorResponse),
      });

      try {
        await service.refreshToken('test-refresh-token');
        expect.fail('Expected to throw');
      } catch {
        expect(createStandardErrorStub.calledOnce).to.be.true;
        expect(createStandardErrorStub.firstCall.args[0]).to.equal(
          'invalid_client'
        );
        expect(createStandardErrorStub.firstCall.args[1]).to.equal(
          'Client authentication failed'
        );
      }
    });
  });

  describe('scope normalization', function () {
    const testCases = [
      {
        input: 'openid profile email',
        expected: 'openid profile email',
        description: 'space-delimited scopes',
      },
      {
        input: 'openid,profile,email',
        expected: 'openid profile email',
        description: 'comma-delimited scopes',
      },
      {
        input: 'openid, profile, email',
        expected: 'openid profile email',
        description: 'comma-delimited with spaces',
      },
      {
        input: ' openid  profile   email ',
        expected: 'openid profile email',
        description: 'extra whitespace',
      },
      {
        input: 'openid,,profile,,email',
        expected: 'openid profile email',
        description: 'empty comma-separated values',
      },
      {
        input: '',
        expected: 'openid profile email',
        description: 'empty scope (fallback to config)',
      },
    ];

    testCases.forEach(({ input, expected, description }) => {
      it(`should normalize ${description}`, async function () {
        const mockTokenResponse = {
          access_token: 'test-token',
          scope: input,
        };

        fetchStub.resolves({
          ok: true,
          json: sinon.stub().resolves(mockTokenResponse),
        });

        const result = await service.exchangeCode(
          'test-code',
          'test-verifier',
          'https://example.com/callback'
        );

        expect(result.scope).to.equal(expected);
      });
    });
  });

  describe('userData extraction', function () {
    it('should extract non-sensitive provider response fields', async function () {
      const mockTokenResponse = {
        access_token: 'test-token',
        token_type: 'Bearer',
        expires_in: 3600,
        custom_field: 'custom_value',
        numeric_field: 42,
        boolean_field: true,
        // These should be filtered out
        client_secret: 'secret',
        code_verifier: 'verifier',
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.userData).to.deep.equal({
        token_type: 'Bearer',
        custom_field: 'custom_value',
        numeric_field: 42,
        boolean_field: true,
      });
    });

    it('should not include userData when no additional fields present', async function () {
      const mockTokenResponse = {
        access_token: 'test-token',
        expires_in: 3600,
      };

      fetchStub.resolves({
        ok: true,
        json: sinon.stub().resolves(mockTokenResponse),
      });

      const result = await service.exchangeCode(
        'test-code',
        'test-verifier',
        'https://example.com/callback'
      );

      expect(result.userData).to.be.undefined;
    });
  });
});
