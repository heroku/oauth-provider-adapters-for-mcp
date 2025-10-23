# Changelog

## 1.0.0 (2025-10-21)

### Features

- **adapters/oidc:** Add openid-client OIDC discovery and refactors error
  handling to take place in the base adapter
  ([#6](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/6))
  ([2160571](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/2160571cfb801c13bbf19e25749937a8113405dd))
- **adapters/oidc:** Implement token exchange and refresh in OIDCProviderAdapter
  ([#8](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/8))
  ([321411c](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/321411c5c5c399eac77c164efdf81fafe5a8ef4d))
- **adapters/oidc:** provider quirk config and validation
  ([#7](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/7))
  ([49cd4df](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/49cd4dff575c632e7491fbf3143dd5c3f9e2b97c))
- Add logger injection
  ([#11](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/11))
  ([1987b55](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/1987b5563d39d33e555467f8b5f2edaa6ab7deff))
- Adds support for static OIDC metadata via environment file
  ([#13](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/13))
  ([3b4de3e](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/3b4de3e6c71b5361a689464725d98099deb0bc2c))
- Base OAuth Adapter
  ([#3](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/3))
  ([872605f](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/872605f5980c3762ae24b1eb3d9524584d782a50))
- implement fromEnvironment helper for OIDC adapter integration
  ([#9](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/9))
  ([622df42](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/622df423215904cd900a5d79dda8329a44c5d5ca))
- initialize provider and generate pcke auth url
  ([#5](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/5))
  ([1c6fb0d](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/1c6fb0d576da1ca65eadf509f37f9d143e999174))
- logger implementation
  ([#4](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/4))
  ([ce8d41d](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/ce8d41d1e7af2380f6fdc8938b1dd02bcd0dd3eb))

### Documentation

- **adapters/oidc:** add adapter/OIDC example and contribution guide
  ([#12](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/12))
  ([59d40fe](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/59d40fee791cda20dd68f85dbc7e5afb52b1e102))
- **readme:** Updates README.md
  ([#2](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/2))
  ([eb1a900](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/eb1a90099beccb7ffa9664b7c2e727aec77aa521))
- Updates tooling and package name documentation
  ([#15](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/15))
  ([53fb0fa](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/53fb0fa94264ce1771d7a93b5f78de4c66ab4c8d))

### Miscellaneous

- Adding manual intervention for release start
  ([#14](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/14))
  ([cb9bb98](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/cb9bb98c0c17cecb61da7f2d39ba62f0b1d74048))
- change to make package public on npm
  ([4a04e8c](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/4a04e8cc135cca1bbc06c0ea9ace321eef19beca))
- configure repo
  ([23bc220](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/23bc220c8e0699e2cf40704a2eb61fe013608c2d))
- make npm package public
  ([#17](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/17))
  ([4a04e8c](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/4a04e8cc135cca1bbc06c0ea9ace321eef19beca))
- Update project to include release and using pnpm for package management
  ([#10](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/10))
  ([6a6ba37](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/6a6ba373d46731419d1b2ad4a7820ca864d97257))
- update to using public fixed ip github runner for public repo actions
  ([#19](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/19))
  ([7ab4344](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/7ab4344baa505023e99eaf2d8c098dcefd238ef8))
- version 1.0.0
  ([#18](https://github.com/heroku/oauth-provider-adapters-for-mcp/issues/18))
  ([53779d0](https://github.com/heroku/oauth-provider-adapters-for-mcp/commit/53779d0b4d072283ce41c914e87c1b97c7d66e98))
