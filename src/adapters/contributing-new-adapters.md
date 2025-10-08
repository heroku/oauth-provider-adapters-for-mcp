## Building and Contributing New OAuth/OIDC Adapters

This project welcomes new provider adapters that follow a consistent, secure,
and testable contract.

### Core contract

All adapters extend `BaseOAuthAdapter` and must implement:

- `initialize(): Promise<void>` — discovery/metadata validation, setup, mark
  `initialized=true`
- `generateAuthUrl(interactionId: string, redirectUrl: string): Promise<string>`
  — include PKCE (if applicable)
- `exchangeCode(code: string, verifier: string, redirectUrl: string): Promise<TokenResponse>`
- `refreshToken(refreshToken: string): Promise<TokenResponse>`
- `protected computeProviderQuirks(): ProviderQuirks` — capability flags

Use `ErrorNormalizer` to convert unknown errors into `OAuthError` consistently.

### OIDC adapter shape (reference)

The included `OIDCProviderAdapter` shows recommended patterns:

- Zod-based config validation (`config.ts`)
- Optional discovery vs static metadata
- PKCE S256 enforcement and secure state storage via `PKCEStorageHook`
- PII-safe structured logging

### File layout for a new adapter

```
src/adapters/<provider>/
  index.ts                 # re-exports
  <provider>-adapter.ts    # main adapter class extends BaseOAuthAdapter
  config.ts                # zod schema + validate/safeValidate
  types.ts                 # provider-specific types and hooks
  token-exchange.ts        # token exchange/refresh abstractions
  utils.ts                 # provider utilities (optional)
  *.test.ts                # unit tests
```

### Configuration validation

Define a Zod schema that enforces exactly one of `issuer` or `metadata` (for
OIDC-like providers) and validates URLs. Export `validate` and `safeValidate`
helpers.

### PKCE storage (production requirement)

If your adapter uses PKCE, require a durable storage hook in production. Use
`enforceProductionStorage` from the base class to prevent unsafe in-memory
fallbacks.

### Error handling

- Wrap provider/HTTP SDK calls with `executeWithResilience` where
  retries/circuit breakers help.
- Normalize all thrown errors via `normalizeError` or `createStandardError`.
- Avoid logging secrets; rely on built-in redaction.

### Tests

- Co-locate `*.test.ts` next to source files

### Adapter acceptance checklist

- Implements all abstract methods from `BaseOAuthAdapter`
- Validates config with Zod
- Enforces PKCE and production-grade storage
- Normalizes errors and adds structured, PII-safe logs
- Includes unit tests and passes
  `pnpm run type-check && pnpm test && pnpm run lint`

### Example adapter: GitHub OAuth (non-OIDC)

This example shows how to build a GitHub OAuth adapter extending
`BaseOAuthAdapter`.

Provider endpoints:

- Authorization: `https://github.com/login/oauth/authorize`
- Token: `https://github.com/login/oauth/access_token`

Key quirks:

- No OIDC discovery; static endpoints only
- No refresh tokens; return `unsupported_grant_type` in `refreshToken`
- Accept header `application/json` recommended for token responses

```ts
import { BaseOAuthAdapter } from '@heroku/mcp-oauth-provider-adapters';
import type {
  ProviderQuirks,
  TokenResponse,
} from '@heroku/mcp-oauth-provider-adapters';

export class GitHubOAuthAdapter extends BaseOAuthAdapter {
  private readonly authorizationEndpoint =
    'https://github.com/login/oauth/authorize';
  private readonly tokenEndpoint =
    'https://github.com/login/oauth/access_token';

  public async initialize(): Promise<void> {
    // No discovery needed for GitHub; validate required config
    if (!this['config'].clientId) {
      throw this.createStandardError(
        'invalid_request',
        'clientId is required',
        { stage: 'initialize' }
      );
    }
    this.initialized = true;
  }

  protected getAuthorizationEndpoint(): string {
    return this.authorizationEndpoint;
  }

  public async generateAuthUrl(
    interactionId: string,
    redirectUrl: string
  ): Promise<string> {
    if (!this.initialized) {
      throw this.createStandardError(
        'invalid_request',
        'Adapter must be initialized before generating auth URL',
        { stage: 'generateAuthUrl' }
      );
    }

    // GitHub does not require PKCE for this flow; include standard params
    const params = {
      client_id: this['config'].clientId,
      redirect_uri: redirectUrl,
      scope: this['config'].scopes.join(' '),
      state: interactionId,
    } as Record<string, string>;

    return this.buildAuthorizeUrl(this.authorizationEndpoint, params);
  }

  public async exchangeCode(
    code: string,
    _verifier: string,
    redirectUrl: string
  ): Promise<TokenResponse> {
    try {
      const raw = await this.executeWithResilience(
        async () => {
          const res = await fetch(this.tokenEndpoint, {
            method: 'POST',
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              client_id: this['config'].clientId,
              client_secret: this['config'].clientSecret,
              code,
              redirect_uri: redirectUrl,
            }),
          });
          if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
          return await res.json();
        },
        {
          endpoint: this.tokenEndpoint,
          maxRetries: 2,
          backoffMs: 300,
          circuitKey: 'github',
        }
      );

      // Normalize GitHub token response
      return {
        accessToken: String(raw.access_token),
        scope: typeof raw.scope === 'string' ? raw.scope : undefined,
      };
    } catch (e) {
      throw this.normalizeError(e, { endpoint: this.tokenEndpoint });
    }
  }

  public async refreshToken(_refreshToken: string): Promise<TokenResponse> {
    // GitHub does not issue refresh tokens for standard OAuth apps
    throw this.createStandardError(
      'unsupported_grant_type',
      'GitHub does not support refresh_token for this flow',
      { endpoint: this.tokenEndpoint, stage: 'refreshToken' }
    );
  }

  protected computeProviderQuirks(): ProviderQuirks {
    return {
      supportsOIDCDiscovery: false,
      requiresPKCE: false,
      supportsRefreshTokens: false,
      customParameters: [],
    };
  }
}
```
