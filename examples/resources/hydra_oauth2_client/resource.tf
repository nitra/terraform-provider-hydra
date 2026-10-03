# Public client (no secret) that exchanges CI OIDC tokens via the
# RFC 7523 jwt-bearer grant (see hydra_trusted_jwt_grant_issuer).
resource "hydra_oauth2_client" "ci" {
  client_id                  = "forgejo-ci"
  client_name                = "Forgejo Actions"
  token_endpoint_auth_method = "none"
  grant_types                = ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
  scope                      = "apicurio:developer"

  jwt_bearer_grant_access_token_lifespan = "10m"
}

# Confidential client: the secret is write-only (never in plan/state).
# Bump client_secret_wo_version to push a rotated secret.
variable "svc_client_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "hydra_oauth2_client" "svc" {
  client_id                = "svc"
  grant_types              = ["client_credentials"]
  scope                    = "svc:read"
  client_secret_wo         = var.svc_client_secret
  client_secret_wo_version = 1

  client_credentials_grant_access_token_lifespan = "15m"
  metadata = jsonencode({
    owner = "platform"
  })
}
