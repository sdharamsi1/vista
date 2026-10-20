# ground-truth.json is the facts-only answer key: each scenario's condition, FSBP coverage, and
# published FSBP control severities. Every bucket starts from the module's hardened default (Block
# Public Access, ACLs disabled, SSE-KMS, versioning, access logging, TLS-only) and lists only what
# differs.
#
# controlled: one setting changed per bucket from that default.
# realistic:  website, media, invoice, configuration, backup, and scratch buckets.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # CORS rule allows origin * to send GET, PUT, and DELETE requests.
    "s3-01" = {
      tier = "controlled"
      name = "design-assets"
      cors = { origins = ["*"], methods = ["GET", "PUT", "DELETE"] }
    }
    # public-read ACL: an AllUsers READ grant on the bucket, which permits listing object keys.
    "s3-02" = {
      tier       = "controlled"
      name       = "build-artifacts"
      public_acl = true
    }
    # Policy allows Principal * s3:GetObject and s3:PutObject when aws:PrincipalOrgID is var.org_id.
    "s3-03" = {
      tier = "controlled"
      name = "shared-datasets"
      policy_statements = [{
        actions   = ["s3:GetObject", "s3:PutObject"]
        condition = { StringEquals = { "aws:PrincipalOrgID" = var.org_id } }
      }]
    }
    # Policy allows Principal * s3:GetObject on every object with no condition.
    "s3-04" = {
      tier              = "controlled"
      name              = "customer-exports"
      policy_statements = [{ actions = ["s3:GetObject"] }]
    }
    # Policy allows Principal * s3:GetObject, s3:PutObject, and s3:DeleteObject with no condition.
    "s3-05" = {
      tier              = "controlled"
      name              = "partner-uploads"
      policy_statements = [{ actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] }]
    }

    # ---------- realistic ----------

    # Static website bucket. Policy allows Principal * s3:GetObject; SSE-S3 and no TLS-only
    # statement (S3 website endpoints serve HTTP only).
    "s3-06" = {
      tier              = "realistic"
      name              = "www"
      website           = true
      sse               = "AES256"
      tls_only          = false
      policy_statements = [{ actions = ["s3:GetObject"] }]
    }
    # Media library; policy allows Principal * s3:GetObject only under the public/ prefix.
    "s3-07" = {
      tier              = "realistic"
      name              = "media-library"
      sse               = "AES256"
      policy_statements = [{ actions = ["s3:GetObject"], prefix = "public/" }]
    }
    # Invoices; policy allows Principal * s3:GetObject with only an aws:Referer StringLike condition.
    "s3-08" = {
      tier = "realistic"
      name = "invoices"
      sse  = "AES256"
      policy_statements = [{
        actions   = ["s3:GetObject"]
        condition = { StringLike = { "aws:Referer" = "https://www.${var.name}.example/*" } }
      }]
    }
    # Application configuration; no setting differs from the module defaults.
    "s3-09" = {
      tier = "realistic"
      name = "app-config"
    }
    # Database backups with Object Lock enabled; no other setting differs from the module defaults.
    "s3-10" = {
      tier        = "realistic"
      name        = "db-backups"
      object_lock = true
    }
    # Scratch space with versioning and server access logging off.
    "s3-11" = {
      tier       = "realistic"
      name       = "tmp-scratch"
      versioning = false
      logging    = false
    }
  }
}
