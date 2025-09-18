import { expect } from 'chai';
import { BaseOAuthAdapter } from './base-adapter.js';
import type { OAuthError, ProviderConfig } from './types.js';
import {
  ConfigurableTestAdapter,
  TokenMappingTestAdapter,
  ErrorThrowingTestAdapter,
  RefreshTokenTestAdapter,
  MemoizationTestAdapter,
} from './testUtils/adapters.js';
import { DefaultLogger } from './logging/logger.js';

describe('BaseOAuthAdapter', () => {
  const mockConfig: ProviderConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    issuer: 'https://example.com',
    scopes: ['openid', 'profile'],
    customParameters: {
      audience: 'test-audience',
    },
  };

  describe('constructor', () => {
    it('should store config as protected readonly property', () => {
      const adapter = new ConfigurableTestAdapter(mockConfig);
      const storedConfig = adapter.getConfig();

      expect(storedConfig).to.equal(mockConfig);
      expect(storedConfig.clientId).to.equal('test-client-id');
      expect(storedConfig.scopes).to.deep.equal(['openid', 'profile']);
      expect(storedConfig.customParameters?.audience).to.equal('test-audience');
    });

    it('should be constructible with minimal config', () => {
      const minimalConfig: ProviderConfig = {
        clientId: 'minimal-client',
        metadata: { authorization_endpoint: 'https://auth.example.com' },
        scopes: ['read'],
      };

      const minimalOptions = {
        tokenResponse: { accessToken: 'x' },
        refreshTokenResponse: { accessToken: 'y' },
        quirks: {
          supportsOIDCDiscovery: false,
          requiresPKCE: false,
          supportsRefreshTokens: false,
          customParameters: [],
        },
      };

      expect(
        () => new ConfigurableTestAdapter(minimalConfig, minimalOptions)
      ).to.not.throw();
    });
  });

  describe('logger', () => {
    it('lazily instantiates and returns a default logger', () => {
      const adapter = new ConfigurableTestAdapter(mockConfig);

      expect(adapter.logger).to.be.instanceOf(DefaultLogger);
    });

    it('memoizes and returns the same instance of logger on each call', () => {
      const adapter = new ConfigurableTestAdapter(mockConfig);

      expect(adapter.logger).to.equal(adapter.logger);
    });
  });

  describe('abstract class behavior', () => {
    it('should be abstract at compile-time but allow runtime instantiation', () => {
      // TypeScript compile-time check - this should fail compilation if uncommented:
      // const adapter = new BaseOAuthAdapter(mockConfig);

      // Runtime instantiation is allowed (runtime check was removed)
      // but the instance cannot be used because abstract methods are not implemented
      expect(() => {
        // @ts-expect-error Testing abstract class instantiation
        new BaseOAuthAdapter(mockConfig);
      }).to.not.throw();
    });

    it('should expose abstract API on subclasses', () => {
      const adapter = new ConfigurableTestAdapter(mockConfig, {
        tokenResponse: { accessToken: 'ok' },
        refreshTokenResponse: { accessToken: 'ok2' },
      });
      expect(adapter).to.be.instanceOf(BaseOAuthAdapter);
      expect(adapter.generateAuthUrl).to.be.a('function');
      expect(adapter.refreshToken).to.be.a('function');
    });
  });

  describe('generateAuthUrl', () => {
    it('should generate URL with required parameters after initialization', async () => {
      const adapter = new ConfigurableTestAdapter(mockConfig, {
        tokenResponse: { accessToken: 'test' },
        refreshTokenResponse: { accessToken: 'refresh' },
        quirks: { customParameters: ['audience'] },
      });
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      // Parse the URL to properly validate its structure
      const parsedUrl = new URL(url);

      // Validate base URL
      expect(parsedUrl.origin).to.equal('https://auth.example.com');
      expect(parsedUrl.pathname).to.equal('/authorize');

      // Validate query parameters
      expect(parsedUrl.searchParams.get('response_type')).to.equal('code');
      expect(parsedUrl.searchParams.get('client_id')).to.equal(
        'test-client-id'
      );
      expect(parsedUrl.searchParams.get('redirect_uri')).to.equal(
        'https://example.com/callback'
      );
      expect(parsedUrl.searchParams.get('scope')).to.equal('openid profile');
      expect(parsedUrl.searchParams.get('state')).to.equal('test-interaction');
    });

    it('should merge custom parameters with base parameters', async () => {
      const configWithCustom = {
        ...mockConfig,
        customParameters: {
          audience: 'test-audience',
          prompt: 'login',
        },
      };

      const adapter = new ConfigurableTestAdapter(configWithCustom, {
        quirks: { customParameters: ['audience'] },
      });
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      // Parse URL to validate structure
      const parsedUrl = new URL(url);

      // Validate custom parameters are included
      expect(parsedUrl.searchParams.get('audience')).to.equal('test-audience');
      expect(parsedUrl.searchParams.get('prompt')).to.equal('login');

      // Validate base parameters are still present
      expect(parsedUrl.searchParams.get('response_type')).to.equal('code');
      expect(parsedUrl.searchParams.get('client_id')).to.equal(
        'test-client-id'
      );
    });

    it('should handle custom parameters that override base parameters', async () => {
      const configWithOverride = {
        ...mockConfig,
        customParameters: {
          scope: 'custom-scope',
          response_type: 'code id_token',
        },
      };

      const adapter = new ConfigurableTestAdapter(configWithOverride, {
        quirks: { customParameters: ['audience'] },
      });
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      // Parse URL to validate structure
      const parsedUrl = new URL(url);

      // Custom parameters should override base parameters
      expect(parsedUrl.searchParams.get('scope')).to.equal('custom-scope');
      expect(parsedUrl.searchParams.get('response_type')).to.equal(
        'code id_token'
      );
      expect(parsedUrl.searchParams.get('client_id')).to.equal(
        'test-client-id'
      );
    });
  });

  describe('normalizeError', () => {
    const adapter = new ConfigurableTestAdapter(mockConfig, {
      tokenResponse: { accessToken: 'access' },
      refreshTokenResponse: { accessToken: 'access2' },
    });

    it('should pass through OAuth-shaped errors', () => {
      const err: OAuthError = {
        statusCode: 400,
        error: 'invalid_request',
        error_description: 'Missing code',
        endpoint: '/token',
        issuer: 'https://example.com',
      };

      const normalized = adapter.exposeNormalizeError(err, {});
      expect(normalized).to.deep.include({
        statusCode: 400,
        error: 'invalid_request',
        error_description: 'Missing code',
      });
    });

    it('should normalize axios-like errors', () => {
      const axiosLike = {
        response: {
          status: 401,
          data: { error: 'unauthorized', error_description: 'bad client' },
        },
      };

      const normalized = adapter.exposeNormalizeError(axiosLike, {
        endpoint: '/token',
      });
      expect(normalized.statusCode).to.equal(401);
      expect(normalized.error).to.equal('unauthorized');
      expect(normalized.error_description).to.equal('bad client');
      expect(normalized.endpoint).to.equal('/token');
      expect(normalized.issuer).to.equal('https://example.com');
    });

    it('should normalize fetch-like response objects', () => {
      const fetchLike = { status: 404, statusText: 'Not Found' };
      const normalized = adapter.exposeNormalizeError(fetchLike, {
        endpoint: '/auth',
      });
      expect(normalized.statusCode).to.equal(404);
      expect(normalized.error).to.equal('invalid_request');
      expect(normalized.error_description).to.equal('Not Found');
      expect(normalized.endpoint).to.equal('/auth');
    });

    it('should normalize native Error instances', () => {
      const timeoutError = new Error('Request timeout after 30s');
      const normalized = adapter.exposeNormalizeError(timeoutError, {});
      expect(normalized.statusCode).to.equal(504);
      expect(normalized.error).to.equal('temporarily_unavailable');
      expect(normalized.error_description).to.include('timeout');
    });

    it('should normalize primitive strings', () => {
      const normalized = adapter.exposeNormalizeError('just failed', {
        issuer: 'x',
      });
      expect(normalized.statusCode).to.equal(500);
      expect(normalized.error).to.equal('server_error');
      expect(normalized.error_description).to.equal('just failed');
      expect(normalized.issuer).to.equal('x');
    });
  });

  describe('token exchange and refresh flows (dummy subclasses)', () => {
    it('exchangeCode: maps provider payload into TokenResponse', async () => {
      const adapter = new TokenMappingTestAdapter(mockConfig);
      const res = await adapter.exchangeCode('code', 'verifier', 'http://cb');
      expect(res).to.deep.equal({
        accessToken: 'A',
        refreshToken: 'R',
        idToken: 'ID',
        expiresIn: 3600,
        scope: 'openid profile',
      });
    });

    it('exchangeCode: normalizes provider-shaped error', async () => {
      const adapter = new ErrorThrowingTestAdapter(mockConfig);
      try {
        await adapter.exchangeCode('code', 'verifier', 'http://cb');
        expect.fail('Expected to throw');
      } catch (err) {
        const e = err as OAuthError;
        expect(e.statusCode).to.equal(400);
        expect(e.error).to.equal('invalid_grant');
        expect(e.error_description).to.equal('bad code');
        expect(e.endpoint).to.equal('/token');
        expect(e.issuer).to.equal('https://example.com');
      }
    });

    it('refreshToken: success returns new accessToken and optional refreshToken', async () => {
      const adapter = new RefreshTokenTestAdapter(mockConfig, true);
      const res = await adapter.refreshToken('OLD_R');
      expect(res).to.deep.equal({ accessToken: 'NEW', refreshToken: 'NEW_R' });
    });

    it('refreshToken: unsupported throws normalized error', async () => {
      const adapter = new RefreshTokenTestAdapter(mockConfig, false);
      try {
        await adapter.refreshToken('anything');
        expect.fail('Expected to throw');
      } catch (err) {
        const e = err as OAuthError;
        expect(e.statusCode).to.equal(400);
        expect(e.error).to.equal('unsupported_grant_type');
        expect(e.error_description).to.match(/not supported/i);
        expect(e.endpoint).to.equal('/token');
      }
    });
  });

  describe('getProviderQuirks', () => {
    it('memoizes computeProviderQuirks across calls', () => {
      const cfg: ProviderConfig = {
        clientId: 'x',
        issuer: 'https://issuer.example',
        scopes: ['openid'],
        customParameters: { audience: 'api' },
      };

      const adapter = new MemoizationTestAdapter(cfg);
      const q1 = adapter.getProviderQuirks();
      const q2 = adapter.getProviderQuirks();
      const q3 = adapter.getProviderQuirks();

      expect(q1).to.equal(q2);
      expect(q2).to.equal(q3);
      expect(adapter.getCallCount()).to.equal(1);
    });

    it('performs no network I/O (no fetch calls)', () => {
      const originalFetch = globalThis.fetch;
      let fetchCalls = 0;
      const anyGlobal: any = globalThis as unknown as { fetch?: unknown };
      // Assign without compile-time error; runtime will still override
      anyGlobal.fetch = ((..._args: unknown[]) => {
        void _args;
        fetchCalls += 1;
        return Promise.reject(new Error('should not be called'));
      }) as typeof globalThis.fetch;

      try {
        const adapter = new ConfigurableTestAdapter({
          clientId: 'x',
          scopes: ['s'],
        });
        const quirks = adapter.getProviderQuirks();
        expect(quirks).to.have.property('requiresPKCE', true);
        expect(fetchCalls).to.equal(0);
      } finally {
        anyGlobal.fetch = originalFetch as unknown as typeof globalThis.fetch;
      }
    });

    it('returns expected shape and customParameters reflect config', () => {
      const cfg: ProviderConfig = {
        clientId: 'a',
        scopes: ['openid', 'profile'],
        issuer: 'https://issuer.example',
        customParameters: { audience: 'api', prompt: 'login' },
      };
      const adapter = new ConfigurableTestAdapter(cfg);
      const quirks = adapter.getProviderQuirks();

      expect(quirks.supportsOIDCDiscovery).to.equal(true);
      expect(quirks.requiresPKCE).to.equal(true);
      expect(quirks.supportsRefreshTokens).to.equal(true);
      expect(quirks.customParameters).to.have.members(['audience', 'prompt']);
    });
  });
});
