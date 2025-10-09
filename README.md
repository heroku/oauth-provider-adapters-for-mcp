# OAuth Provider Adapter Library for MCP Servers

An OAuth/OIDC adapter framework designed to make adding identity providers to
Remote MCP servers simple, consistent, and testable.

This project provides a base adapter contract, structured logging, and a
standards-compliant OIDC provider implementation (discovery, PKCE S256, code
exchange, refresh) with normalized errors and configuration validation.

## Why this exists

- Normalize provider integrations behind a single contract
- Enforce consistent error handling and structured, PII-safe logging
- Support OIDC discovery + PKCE, authorization code exchange, and token refresh
- Make adapters independently testable with clear types and acceptance criteria

## Scripts

```bash
pnpm run build      # builds CJS + ESM to dist/
pnpm test           # runs unit tests with coverage (c8 + mocha)
pnpm run lint       # eslint
pnpm run type-check # tsc --noEmit
```

## License

Apache-2.0. See `LICENSE` for details.

## Contributing

We welcome issues and PRs. Please follow conventional commits, keep changes
under 200 lines per commit, and ensure tests and type checks pass. See
`CONTRIBUTING.md` for details.
