# Changelog

## 1.0.0 (unreleased)

First release of the `nitra/hydra` fork of `svrakitin/terraform-provider-hydra`.

BREAKING CHANGES (vs. upstream 0.5.x):

* Provider address `registry.opentofu.org/nitra/hydra`; rewritten on terraform-plugin-framework (protocol 6).
* Removed `hydra_jwks` resource and data source (private keys in state).
* `hydra_oauth2_client`: `client_id` is required; `client_secret` removed in favour of write-only
  `client_secret_wo` + `client_secret_wo_version` (OpenTofu >= 1.11); `metadata` and `jwks` are JSON strings.

FEATURES:

* API client generated from Ory Hydra v26.2.0 (vendored in `internal/httpclient`).
* `hydra_oauth2_client`: all v26.2.0 fields incl. `skip_consent`, `skip_logout_consent`,
  `access_token_strategy` and the 13 lifespans; semantic equality for durations and JSON;
  drift detection (404 -> re-create).
* New resource `hydra_trusted_jwt_grant_issuer` and data source `hydra_trusted_jwt_grant_issuers`.
* Acceptance tests and empirical Hydra v26.2.0 checks against a local `oryd/hydra:v26.2.0` (podman/docker compose).
