import { expect } from 'chai';
import { BaseOAuthAdapter } from './base-adapter.js';
import type { OAuthError, ProviderConfig } from './types.js';

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
      class TestAdapter extends BaseOAuthAdapter {
        public getConfig() {
          return this.config;
        }
        public async initialize(): Promise<void> {
          return;
        }
        public async generateAuthUrl(
          interactionId: string,
          redirectUrl: string
        ): Promise<string> {
          return `${interactionId}:${redirectUrl}`;
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 't' };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 'r' };
        }
        public getProviderQuirks(): import('./types.js').ProviderQuirks {
          return {
            supportsOIDCDiscovery: true,
            requiresPKCE: true,
            supportsRefreshTokens: true,
            customParameters: [],
          };
        }
      }

      const adapter = new TestAdapter(mockConfig);
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

      class MinimalTestAdapter extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        public async generateAuthUrl(
          interactionId: string,
          redirectUrl: string
        ): Promise<string> {
          return `${interactionId}:${redirectUrl}`;
        }
        public async exchangeCode(
          _code: string,
          _verifier: string,
          _redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 'x' };
        }
        public async refreshToken(
          _refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 'y' };
        }
        public getProviderQuirks(): import('./types.js').ProviderQuirks {
          return {
            supportsOIDCDiscovery: false,
            requiresPKCE: false,
            supportsRefreshTokens: false,
            customParameters: [],
          };
        }
      }

      expect(() => new MinimalTestAdapter(minimalConfig)).to.not.throw();
    });
  });

  describe('abstract class behavior', () => {
    it('should be abstract and not directly instantiable', () => {
      // TypeScript compile-time check - this should fail compilation if uncommented:
      // const adapter = new BaseOAuthAdapter(mockConfig);

      // Runtime verification that the class is meant to be abstract
      expect(() => {
        // @ts-expect-error Testing abstract class instantiation
        new BaseOAuthAdapter(mockConfig);
      }).to.throw();
    });

    it('should expose abstract API on subclasses', () => {
      class Impl extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return `${i}:${r}`;
        }
        public async exchangeCode(
          _c: string,
          _v: string,
          _r: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 'ok' };
        }
        public async refreshToken(
          _t: string
        ): Promise<import('./types.js').TokenResponse> {
          return { accessToken: 'ok2' };
        }
        public getProviderQuirks(): import('./types.js').ProviderQuirks {
          return {
            supportsOIDCDiscovery: true,
            requiresPKCE: true,
            supportsRefreshTokens: true,
            customParameters: [],
          };
        }
      }

      const adapter = new Impl(mockConfig);
      expect(adapter).to.be.instanceOf(BaseOAuthAdapter);
      expect(adapter.generateAuthUrl).to.be.a('function');
      expect(adapter.refreshToken).to.be.a('function');
    });
  });

  describe('normalizeError', () => {
    class TestAdapter extends BaseOAuthAdapter {
      public async initialize(): Promise<void> {
        return;
      }
      public async generateAuthUrl(
        interactionId: string,
        redirectUrl: string
      ): Promise<string> {
        return `${interactionId}:${redirectUrl}`;
      }
      public async exchangeCode(
        _code: string,
        _verifier: string,
        _redirectUrl: string
      ): Promise<import('./types.js').TokenResponse> {
        return {
          accessToken: 'access',
        };
      }
      public async refreshToken(
        _refreshToken: string
      ): Promise<import('./types.js').TokenResponse> {
        return { accessToken: 'access2' };
      }
      public getProviderQuirks(): import('./types.js').ProviderQuirks {
        return {
          supportsOIDCDiscovery: true,
          requiresPKCE: true,
          supportsRefreshTokens: true,
          customParameters: [],
        };
      }

      public exposeNormalize(
        e: unknown,
        c: { endpoint?: string; issuer?: string }
      ): OAuthError {
        return (
          this as unknown as {
            normalizeError: (
              e: unknown,
              c: { endpoint?: string; issuer?: string }
            ) => OAuthError;
          }
        ).normalizeError(e, c);
      }
    }

    const adapter = new TestAdapter(mockConfig);

    it('should pass through OAuth-shaped errors', () => {
      const err: OAuthError = {
        statusCode: 400,
        error: 'invalid_request',
        error_description: 'Missing code',
        endpoint: '/token',
        issuer: 'https://example.com',
      };

      const normalized = adapter.exposeNormalize(err, {});
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

      const normalized = adapter.exposeNormalize(axiosLike, {
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
      const normalized = adapter.exposeNormalize(fetchLike, {
        endpoint: '/auth',
      });
      expect(normalized.statusCode).to.equal(404);
      expect(normalized.error).to.equal('invalid_request');
      expect(normalized.error_description).to.equal('Not Found');
      expect(normalized.endpoint).to.equal('/auth');
    });

    it('should normalize native Error instances', () => {
      const timeoutError = new Error('Request timeout after 30s');
      const normalized = adapter.exposeNormalize(timeoutError, {});
      expect(normalized.statusCode).to.equal(504);
      expect(normalized.error).to.equal('temporarily_unavailable');
      expect(normalized.error_description).to.include('timeout');
    });

    it('should normalize primitive strings', () => {
      const normalized = adapter.exposeNormalize('just failed', {
        issuer: 'x',
      });
      expect(normalized.statusCode).to.equal(500);
      expect(normalized.error).to.equal('server_error');
      expect(normalized.error_description).to.equal('just failed');
      expect(normalized.issuer).to.equal('x');
    });
  });
});
