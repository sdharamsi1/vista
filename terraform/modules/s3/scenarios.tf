# Expected ratings are in ground-truth.json. Every bucket starts hardened (Block Public Access,
# ACLs disabled, SSE-KMS, versioning, access logging, TLS-only) and lists only what differs.
#
# controlled: the single-flaw severity ladder.
# realistic:  expected, ambiguous, and messy cases mixed in with ordinary well-configured buckets.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # LOW: CORS lets any origin send PUT and DELETE requests.
    "s3-01" = {
      tier = "controlled"
      name = "design-assets"
      cors = { origins = ["*"], methods = ["GET", "PUT", "DELETE"] }
    }
    # MEDIUM: public-read ACL lets anyone list object names, but not read objects.
    "s3-02" = {
      tier       = "controlled"
      name       = "build-artifacts"
      public_acl = true
    }
    # MEDIUM: wildcard principal can read and write objects from any account in the organization.
    "s3-03" = {
      tier = "controlled"
      name = "shared-datasets"
      policy_statements = [{
        actions   = ["s3:GetObject", "s3:PutObject"]
        condition = { StringEquals = { "aws:PrincipalOrgID" = var.org_id } }
      }]
    }
    # HIGH: bucket policy lets anyone on the Internet read every object.
    "s3-04" = {
      tier              = "controlled"
      name              = "customer-exports"
      policy_statements = [{ actions = ["s3:GetObject"] }]
    }
    # CRITICAL: bucket policy lets anyone on the Internet read, overwrite, and delete objects.
    "s3-05" = {
      tier              = "controlled"
      name              = "partner-uploads"
      policy_statements = [{ actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] }]
    }

    # ---------- realistic ----------

    # EXPECTED: static website bucket. Anonymous read is the point; SSE-S3 and no TLS-only rule
    # because S3 website endpoints serve plain HTTP.
    "s3-06" = {
      tier              = "realistic"
      name              = "www"
      website           = true
      sse               = "AES256"
      tls_only          = false
      policy_statements = [{ actions = ["s3:GetObject"] }]
    }
    # AMBIGUOUS: media library where only the public/ prefix is anonymously readable.
    "s3-07" = {
      tier              = "realistic"
      name              = "media-library"
      sse               = "AES256"
      policy_statements = [{ actions = ["s3:GetObject"], prefix = "public/" }]
    }
    # HIGH: "only our website can read invoices", enforced with aws:Referer, which any client can set.
    "s3-08" = {
      tier = "realistic"
      name = "invoices"
      sse  = "AES256"
      policy_statements = [{
        actions   = ["s3:GetObject"]
        condition = { StringLike = { "aws:Referer" = "https://www.${var.name}.example/*" } }
      }]
    }
    # EXPECTED: application configuration, fully hardened.
    "s3-09" = {
      tier = "realistic"
      name = "app-config"
    }
    # EXPECTED: database backups with Object Lock enabled, fully hardened.
    "s3-10" = {
      tier        = "realistic"
      name        = "db-backups"
      object_lock = true
    }
    # LOW: scratch space with no versioning and no access logging, otherwise private.
    "s3-11" = {
      tier       = "realistic"
      name       = "tmp-scratch"
      versioning = false
      logging    = false
    }
  }
}
