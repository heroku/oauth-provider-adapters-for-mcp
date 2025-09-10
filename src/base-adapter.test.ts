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
          await super.initialize();
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(
          interactionId: string,
          redirectUrl: string
        ): Promise<string> {
          return super.generateAuthUrl(interactionId, redirectUrl);
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          return { accessToken: 't' };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
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
          await super.initialize();
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(
          interactionId: string,
          redirectUrl: string
        ): Promise<string> {
          return super.generateAuthUrl(interactionId, redirectUrl);
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          return { accessToken: 'x' };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
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
          await super.initialize();
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return super.generateAuthUrl(i, r);
        }
        public async exchangeCode(
          c: string,
          v: string,
          r: string
        ): Promise<import('./types.js').TokenResponse> {
          void c;
          void v;
          void r;
          return { accessToken: 'ok' };
        }
        public async refreshToken(
          t: string
        ): Promise<import('./types.js').TokenResponse> {
          void t;
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

  describe('generateAuthUrl', () => {
    class TestAdapter extends BaseOAuthAdapter {
      public async initialize(): Promise<void> {
        await super.initialize();
      }
      protected getAuthorizationEndpoint(): string {
        return 'https://auth.example.com/authorize';
      }

      public async exchangeCode(
        _code: string,
        _verifier: string,
        _redirectUrl: string
      ): Promise<import('./types.js').TokenResponse> {
        return { accessToken: 'test' };
      }

      public async refreshToken(
        _refreshToken: string
      ): Promise<import('./types.js').TokenResponse> {
        return { accessToken: 'refresh' };
      }

      public getProviderQuirks(): import('./types.js').ProviderQuirks {
        return {
          supportsOIDCDiscovery: true,
          requiresPKCE: true,
          supportsRefreshTokens: true,
          customParameters: ['audience'],
        };
      }
    }

    it('should throw normalized error if not initialized', async () => {
      const adapter = new TestAdapter(mockConfig);

      try {
        await adapter.generateAuthUrl(
          'test-interaction',
          'https://example.com/callback'
        );
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.have.property('statusCode', 500);
        expect(error).to.have.property('error', 'server_error');
        expect(error).to.have.property('error_description');
        expect(error).to.have.property('endpoint', 'generateAuthUrl');
        expect(error).to.have.property('issuer', 'https://example.com');
      }
    });

    it('should generate URL with required parameters after initialization', async () => {
      const adapter = new TestAdapter(mockConfig);
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      expect(url).to.include('https://auth.example.com/authorize');
      expect(url).to.include('response_type=code');
      expect(url).to.include('client_id=test-client-id');
      expect(url).to.include(
        'redirect_uri=https%3A%2F%2Fexample.com%2Fcallback'
      ); // URL-encoded
      expect(url).to.include('scope=openid+profile');
      expect(url).to.include('state=test-interaction');
    });

    it('should merge custom parameters with base parameters', async () => {
      const configWithCustom = {
        ...mockConfig,
        customParameters: {
          audience: 'test-audience',
          prompt: 'login',
        },
      };

      const adapter = new TestAdapter(configWithCustom);
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      expect(url).to.include('audience=test-audience');
      expect(url).to.include('prompt=login');
      expect(url).to.include('response_type=code');
      expect(url).to.include('client_id=test-client-id');
    });

    it('should handle custom parameters that override base parameters', async () => {
      const configWithOverride = {
        ...mockConfig,
        customParameters: {
          scope: 'custom-scope',
          response_type: 'code id_token',
        },
      };

      const adapter = new TestAdapter(configWithOverride);
      await adapter.initialize();

      const url = await adapter.generateAuthUrl(
        'test-interaction',
        'https://example.com/callback'
      );

      // Custom parameters should override base parameters
      expect(url).to.include('scope=custom-scope');
      expect(url).to.include('response_type=code+id_token');
      expect(url).to.include('client_id=test-client-id');
    });
  });

  describe('normalizeError', () => {
    class TestAdapter extends BaseOAuthAdapter {
      public async initialize(): Promise<void> {
        await super.initialize();
      }
      protected getAuthorizationEndpoint(): string {
        return 'https://auth.example.com/authorize';
      }
      public async generateAuthUrl(
        interactionId: string,
        redirectUrl: string
      ): Promise<string> {
        return super.generateAuthUrl(interactionId, redirectUrl);
      }
      public async exchangeCode(
        code: string,
        verifier: string,
        redirectUrl: string
      ): Promise<import('./types.js').TokenResponse> {
        void code;
        void verifier;
        void redirectUrl;
        return {
          accessToken: 'access',
        };
      }
      public async refreshToken(
        refreshToken: string
      ): Promise<import('./types.js').TokenResponse> {
        void refreshToken;
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

  describe('token exchange and refresh flows (dummy subclasses)', () => {
    it('exchangeCode: maps provider payload into TokenResponse', async () => {
      class DummySuccess extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return `${i}:${r}`;
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          // Simulate provider response mapping
          const provider = {
            access_token: 'A',
            refresh_token: 'R',
            id_token: 'ID',
            expires_in: 3600,
            scope: 'openid profile',
          } as const;
          return {
            accessToken: provider.access_token,
            refreshToken: provider.refresh_token,
            idToken: provider.id_token,
            expiresIn: provider.expires_in,
            scope: provider.scope,
          };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
          return { accessToken: 'X' };
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

      const adapter = new DummySuccess(mockConfig);
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
      class DummyError extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return `${i}:${r}`;
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          try {
            // Simulate provider throwing an HTTP-like error
            throw {
              response: {
                status: 400,
                data: { error: 'invalid_grant', error_description: 'bad code' },
              },
            };
          } catch (e) {
            // Re-throw normalized OAuthError
            throw (
              this as unknown as {
                normalizeError: (
                  e: unknown,
                  c: { endpoint?: string; issuer?: string }
                ) => OAuthError;
              }
            ).normalizeError(e, { endpoint: '/token' });
          }
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
          return { accessToken: 'X' };
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

      const adapter = new DummyError(mockConfig);
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
      class DummyRefresh extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return `${i}:${r}`;
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          return { accessToken: 'X' };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
          const provider = {
            access_token: 'NEW',
            refresh_token: 'NEW_R',
          } as const;
          return {
            accessToken: provider.access_token,
            refreshToken: provider.refresh_token,
          };
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

      const adapter = new DummyRefresh(mockConfig);
      const res = await adapter.refreshToken('OLD_R');
      expect(res).to.deep.equal({ accessToken: 'NEW', refreshToken: 'NEW_R' });
    });

    it('refreshToken: unsupported throws normalized error', async () => {
      class DummyNoRefresh extends BaseOAuthAdapter {
        public async initialize(): Promise<void> {
          return;
        }
        protected getAuthorizationEndpoint(): string {
          return 'https://auth.example.com/authorize';
        }
        public async generateAuthUrl(i: string, r: string): Promise<string> {
          return `${i}:${r}`;
        }
        public async exchangeCode(
          code: string,
          verifier: string,
          redirectUrl: string
        ): Promise<import('./types.js').TokenResponse> {
          void code;
          void verifier;
          void redirectUrl;
          return { accessToken: 'X' };
        }
        public async refreshToken(
          refreshToken: string
        ): Promise<import('./types.js').TokenResponse> {
          void refreshToken;
          const unsupported: OAuthError = {
            statusCode: 400,
            error: 'unsupported_grant_type',
            error_description: 'Refresh token not supported',
          };
          throw (
            this as unknown as {
              normalizeError: (
                e: unknown,
                c: { endpoint?: string; issuer?: string }
              ) => OAuthError;
            }
          ).normalizeError(unsupported, { endpoint: '/token' });
        }
        public getProviderQuirks(): import('./types.js').ProviderQuirks {
          return {
            supportsOIDCDiscovery: true,
            requiresPKCE: true,
            supportsRefreshTokens: false,
            customParameters: [],
          };
        }
      }

      const adapter = new DummyNoRefresh(mockConfig);
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
});
