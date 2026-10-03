data "hydra_trusted_jwt_grant_issuers" "ci" {
  issuer = "https://ci.example.com"
}

output "trust_ids_by_kid" {
  value = { for t in data.hydra_trusted_jwt_grant_issuers.ci.issuers : t.kid => t.id }
}
