resource "hydra_trusted_jwt_grant_issuer" "ci" {
  issuer  = "https://ci.example.com"
  subject = "repo:org/app:ref:refs/heads/main"
  scope   = ["apicurio:developer"]
  jwk = jsonencode({
    kty = "RSA"
    kid = "ci-2026"
    alg = "RS256"
    use = "sig"
    n   = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    e   = "AQAB"
  })
  # Fixed, far-away expiry: not rotated (see the guide for why).
  expires_at = "2036-10-01T00:00:00Z"
}
