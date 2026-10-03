# Vendored Ory Hydra Go client (`hydra-client-go/v2`)

This directory is an unmodified copy of `internal/httpclient` from
[ory/hydra](https://github.com/ory/hydra) at tag **`v26.2.0`**
(commit `0b84568fffccf151dc5e6c7955fdfb738555bf4b`). Only the generated Go
sources, `go.mod` and `go.sum` were copied (the generated `docs/`, `api/`
OpenAPI spec and `git_push.sh` were left out).

It is wired in through a `replace` directive in the root `go.mod`:

```
replace github.com/ory/hydra-client-go/v2 => ./internal/httpclient
```

Why vendored instead of the published `github.com/ory/hydra-client-go/v2`:
the published module (v2.x) lags the server and does not match the
`OAuth2Client` model of Hydra v26.2.0 (`skip_logout_consent`,
`device_authorization_grant_*` lifespans, `access_token_strategy`, ...).
Pinning the client generated from the exact server tag we run keeps the
provider and the server in lock-step.

Known limitation of the generated code that the provider works around (not
patched here): request-side models such as `JsonWebKey` and
`TrustOAuth2JwtGrantIssuer` use a strict `UnmarshalJSON` (required `alg`,
`kid`, `kty`, `use`; unknown fields rejected). JWKs published by third parties
(e.g. Forgejo Actions) may omit `use`/`alg` or carry extra members such as
`x5t`, so `hydra_trusted_jwt_grant_issuer` posts the JWK as raw JSON instead
of going through `JsonWebKey`.

License: Apache License 2.0, Copyright Ory Corp - see `LICENSE` in this
directory. To update, copy `internal/httpclient` from the new Hydra tag and
update the tag/commit above.
