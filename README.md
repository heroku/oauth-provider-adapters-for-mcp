# MCP OAuth Provider Adapter Library

An OAuth/OIDC adapter framework designed to make adding identity providers to
Remote MCP servers simple, consistent, and testable.

This project provides a base adapter contract, structured logging, and a
standards-compliant OIDC provider implementation (discovery, PKCE S256, code
exchange, refresh) with normalized errors and configuration validation.

## Benefits

- Normalize provider integrations behind a single contract
- Enforce consistent error handling and structured, PII-safe logging
- Support OIDC discovery + PKCE, authorization code exchange, and token refresh
- Make adapters independently testable with clear types and acceptance criteria

## Scripts

A list of useful scripts when developing against the codebase:

```bash
pnpm run build      # builds CJS + ESM to dist/
pnpm test           # runs unit tests with coverage (c8 + mocha)
pnpm run lint       # eslint
pnpm run type-check # tsc --noEmit
```

## Implementing OIDC in a Remote MCP Server (with Auth0 Example)

This guide shows how to integrate `mcp-oauth-provider-adapters` into a remote
MCP server and implement an OIDC provider using both discovery and static
metadata. It uses
`[remote MCP with Auth0 from Cloudflare](https://github.com/cloudflare/ai/tree/main/demos/remote-mcp-auth0)`
as an example.

### Prerequisites

- Node.js ≥ 20
- An OIDC provider (for example, Auth0 Tenant)
- A remote MCP server (for example, Cloudflare Workers or Node server)
- [MCP Remote Auth Proxy](https://github.com/heroku/mcp-remote-auth-proxy) - An
  MCP auth proxy within your Heroku app that enables you to use a remote MCP
  server

### Install

- npm:

  ```bash
  npm install @heroku/oauth-provider-adapters-for-mcp
  ```

- pnpm:

  ```bash
  pnpm add @heroku/oauth-provider-adapters-for-mcp
  ```

- yarn:

  ```bash
  yarn add @heroku/oauth-provider-adapters-for-mcp
  ```

### Choose a Configuration Mode

You can configure the `OIDCProviderAdapter` with:

- **Discovery**: Provide an `issuer` (recommended)
- **Static metadata**: Provide `metadata` (useful in restricted environments)

You must provide exactly one of `issuer` or `metadata`.

### Quickstart with Auth0 (Discovery)

Auth0 issuer pattern: `https://<your-tenant>.auth0.com`

```ts
import { OIDCProviderAdapter } from '@heroku/oauth-provider-adapters-for-mcp';

const adapter = new OIDCProviderAdapter({
  clientId: process.env.IDENTITY_CLIENT_ID!,
  clientSecret: process.env.IDENTITY_CLIENT_SECRET,
  issuer: `https://${process.env.AUTH0_TENANT}.auth0.com`,
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  // Redirect URI must match your app registration
  redirectUri: process.env.IDENTITY_REDIRECT_URI,
  // Auth0 often requires audience for API access (optional)
  customParameters: process.env.AUTH0_AUDIENCE
    ? { audience: process.env.AUTH0_AUDIENCE }
    : undefined,
});

await adapter.initialize();

// Begin login flow (inside your authorize endpoint)
const state = crypto.randomUUID();
const authUrl = await adapter.generateAuthUrl(
  state,
  process.env.IDENTITY_REDIRECT_URI!
);
// Redirect user to authUrl

// Handle OAuth callback
// Retrieve the `code` from the OAuth callback query parameters (for example, `req.query.code` or `event.queryStringParameters.code`)
// Retrieve the PKCE `code_verifier` you previously stored for this interaction (for example, from a secure session, database, or in-memory store keyed by `state`)
const tokens = await adapter.exchangeCode(
  code,
  codeVerifier,
  process.env.IDENTITY_REDIRECT_URI!
);
// tokens: { accessToken, refreshToken?, idToken?, expiresIn?, scope? }

// Later: refresh token
const refreshed = await adapter.refreshToken(tokens.refreshToken!);
```

Environment variables commonly used with Auth0:

```bash
IDENTITY_CLIENT_ID=<auth0 client id>
IDENTITY_CLIENT_SECRET=<auth0 client secret>
AUTH0_TENANT=<tenant subdomain>
AUTH0_AUDIENCE=<optional resource API identifier>
IDENTITY_REDIRECT_URI=https://<your-remote-mcp-host>/oauth/callback
```

For most use cases, you can simplify configuration by using the
`fromEnvironmentAsync` convenience helper. It reduces boilerplate and helps
ensure your adapter is configured consistently across environments. It's
especially useful in production or CI/CD setups, where secrets and configuration
are injected via environment variables, and helps prevent accidental
misconfiguration. This helper automatically reads all required OIDC
configurations from the supported environment variables.

Supported environment variables:

- `IDENTITY_CLIENT_ID` -> clientId
- `IDENTITY_CLIENT_SECRET` -> clientSecret
- `IDENTITY_SERVER_URL` -> issuer (for OIDC discovery)
- `IDENTITY_SERVER_METADATA_FILE` -> metadata (static metadata file, skips
  discovery)
- `IDENTITY_REDIRECT_URI` -> redirectUri
- `IDENTITY_SCOPE` -> scopes (split by spaces and commas)

You can still override or extend the configuration by passing additional
options, such as `customParameters` for provider-specific needs (for example,
Auth0's `audience`).

### Using Static Metadata Example (No Discovery)

Fetch your provider’s metadata from `/.well-known/openid-configuration`, then
embed a subset:

```ts
import { OIDCProviderAdapter } from '@heroku/oauth-provider-adapters-for-mcp';

const adapter = new OIDCProviderAdapter({
  clientId: process.env.IDENTITY_CLIENT_ID!,
  clientSecret: process.env.IDENTITY_CLIENT_SECRET,
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  redirectUri: process.env.IDENTITY_REDIRECT_URI,
  metadata: {
    issuer: `https://${process.env.AUTH0_TENANT}.auth0.com`,
    authorization_endpoint: `https://${process.env.AUTH0_TENANT}.auth0.com/authorize`,
    token_endpoint: `https://${process.env.AUTH0_TENANT}.auth0.com/oauth/token`,
    jwks_uri: `https://${process.env.AUTH0_TENANT}.auth0.com/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  },
  customParameters: process.env.AUTH0_AUDIENCE
    ? { audience: process.env.AUTH0_AUDIENCE }
    : undefined,
});

await adapter.initialize();
```

### PKCE State Storage

`OIDCProviderAdapter` requires storing the PKCE verifier securely between the
authorize and callback steps. In development, an in-memory mock is used. In
production, you must provide a durable `storageHook`:

```ts
interface PKCEStorageHook {
  storePKCEState(
    interactionId: string,
    state: string,
    codeVerifier: string,
    expiresAt: number
  ): Promise<void>;
  retrievePKCEState(
    interactionId: string,
    state: string
  ): Promise<string | null>;
  cleanupExpiredState(beforeTimestamp: number): Promise<void>;
}
```

Examples:
[Heroku Key-Value Store](https://devcenter.heroku.com/articles/heroku-redis),
Redis, or your database.

### Connecting to a Remote MCP Server

At minimum, your server needs routes that:

- Start the auth flow and redirect to `await adapter.generateAuthUrl(...)`
- Handle the callback, verify `state`, load `code_verifier`, and call
  `adapter.exchangeCode(...)`
- Optionally expose a refresh path that calls `adapter.refreshToken(...)`

### Error Handling and Logging

Errors are normalized to:

```ts
type OAuthError = {
  statusCode: number;
  error: string;
  error_description?: string;
  endpoint?: string;
  issuer?: string;
};
```

#### Logger Injection

The adapter performs PII-safe, structured logging and retries with backoff for
discovery. In addition, we support logger injection with `LogTransport` so logs
integrate with your observability stack. Here's an example of how to demo
logging capabilities using the `winston` logger used in `mcp-remote-auth-proxy`.

1. Import required types:

```javascript
import {
  fromEnvironmentAsync,
  DefaultLogger,
  LogLevel,
} from '@heroku/oauth-provider-adapters-for-mcp';
import winstonLogger from './winstonLogger.js';
```

2. Create a LogTransport wrapper:

```javascript
// Create a LogTransport that wraps Winston
const winstonTransport = {
  log: (message) => {
    // Winston child logger preserves request context and Splunk formatting
    const contextLogger = winstonLogger.child({ component: 'oidc-adapter' });
    contextLogger.info(message);
  },
  error: (message) => {
    const contextLogger = winstonLogger.child({ component: 'oidc-adapter' });
    contextLogger.error(message);
  },
};
```

3. Create DefaultLogger with the Winston transport:

```javascript
// Create DefaultLogger that uses Winston as transport
const adapterLogger = new DefaultLogger(
  { component: 'oidc-adapter' }, // Base context
  {
    level: LogLevel.Info,
    redactPaths: [], // DefaultLogger already has OAuth redaction built-in
  },
  winstonTransport // Use Winston as the transport
);
```

4. Pass the logger to the adapter:

```javascript
const oidcAdapter = await fromEnvironmentAsync({
  env: adapterEnv,
  storageHook,
  defaultScopes: IDENTITY_SCOPE_parsed,
  logger: adapterLogger,
});
```

## License

Apache-2.0. See `LICENSE` for details.

## Contributing

We welcome issues and PRs. Please follow conventional commits, keep changes
under 200 lines per commit, and ensure tests and type checks pass. See
`CONTRIBUTING.md` for details.
