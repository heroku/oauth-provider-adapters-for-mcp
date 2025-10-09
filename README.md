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

## Code Quality and Testing

This project uses pnpm for package management and includes comprehensive code
quality tools to maintain high standards.

### Available Scripts

```bash

# Run the full Mocha test suite with c8 coverage reporting
pnpm test

# Check code quality with ESLint
pnpm lint

# Automatically fix linting issues and format code with Prettier
pnpm format

# Run TypeScript type checking on *.ts files
pnpm type-check

# All code quality checks and tests
pnpm check

# Run the continuous integration checks (linting, type checking, and tests):
pnpm ci
```

### Development Workflow

For the best development experience:

1. **Before starting work**: Ensure dependencies are installed with
   `pnpm install`
2. **During development**: Run `pnpm type-check` periodically to catch type
   errors early
3. **Before committing**: Run `pnpm check` to ensure all quality standards are
   met
4. **Fix issues quickly**: Use `pnpm format` to auto-fix formatting and linting
   issues

### Testing Requirements

Tests are located in `src/**/*.test.ts` and run against the compiled JavaScript
in `dist/cjs/`. The test suite includes:

- Unit tests for all public APIs
- Mock-based testing for external dependencies
- Coverage reporting with c8 (HTML and text-summary)

Tests automatically run in silent mode (`LOG_LEVEL=silent`) to keep output
clean.

### Build Outputs

The library produces dual builds for maximum compatibility:

- **CommonJS** (`dist/cjs/`): For Node.js and older bundlers
- **ES Modules** (`dist/esm/`): For modern bundlers and tree-shaking support

Both outputs include TypeScript declaration files (`.d.ts`) for type
information.

## License

Apache-2.0. See `LICENSE` for details.

## Contributing

We welcome issues and PRs. Please follow conventional commits, keep changes
under 200 lines per commit, and ensure tests and type checks pass. See
`CONTRIBUTING.md` for details.
