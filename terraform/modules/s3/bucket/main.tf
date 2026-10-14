# One scenario bucket: Block Public Access, ACLs disabled, SSE-KMS, versioning, access logging,
# and TLS-only access, unless config says otherwise.

locals {
  # Condition keys that Block Public Access treats as restricting a Principal "*" grant. A
  # statement with no condition, or only other keys (such as aws:Referer), is public.
  restricting_keys = ["aws:PrincipalOrgID", "aws:SourceIp", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceArn", "aws:SourceAccount"]
  public_policy = anytrue([
    for statement in var.config.policy_statements :
    length(setintersection(flatten([for operator, entries in statement.condition : keys(entries)]), local.restricting_keys)) == 0
  ])
}

resource "aws_s3_bucket" "this" {
  bucket              = var.name
  force_destroy       = true
  object_lock_enabled = var.config.object_lock
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = !var.config.public_acl
  ignore_public_acls      = !var.config.public_acl
  block_public_policy     = !local.public_policy
  restrict_public_buckets = !local.public_policy
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = var.config.public_acl ? "BucketOwnerPreferred" : "BucketOwnerEnforced"
  }
}

# Grants the AllUsers group READ on the bucket, which lets anyone list its objects.
resource "aws_s3_bucket_acl" "public" {
  count      = var.config.public_acl ? 1 : 0
  bucket     = aws_s3_bucket.this.id
  acl        = "public-read"
  depends_on = [aws_s3_bucket_ownership_controls.this, aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    bucket_key_enabled = var.config.sse == "aws:kms"

    apply_server_side_encryption_by_default {
      sse_algorithm = var.config.sse
    }
  }
}

# Without this resource a new bucket is simply unversioned.
resource "aws_s3_bucket_versioning" "this" {
  count  = var.config.versioning || var.config.object_lock ? 1 : 0
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "this" {
  count         = var.config.logging ? 1 : 0
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.log_bucket
  target_prefix = "${var.name}/"
}

resource "aws_s3_bucket_website_configuration" "this" {
  count  = var.config.website ? 1 : 0
  bucket = aws_s3_bucket.this.id

  index_document {
    suffix = "index.html"
  }
  error_document {
    key = "error.html"
  }
}

resource "aws_s3_bucket_cors_configuration" "this" {
  count  = var.config.cors == null ? 0 : 1
  bucket = aws_s3_bucket.this.id

  cors_rule {
    allowed_origins = var.config.cors.origins
    allowed_methods = var.config.cors.methods
    allowed_headers = ["*"]
  }
}

# Denies non-TLS requests unless tls_only is false (S3 website endpoints are HTTP-only); scenario
# statements grant Principal "*" access to objects, optionally under one prefix.
locals {
  tls_statement = var.config.tls_only ? [{
    Sid       = "DenyInsecureTransport"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource  = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] : []
  grant_statements = [
    for statement in var.config.policy_statements : merge(
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = statement.actions
        Resource  = "${aws_s3_bucket.this.arn}/${statement.prefix}*"
      },
      length(statement.condition) > 0 ? { Condition = statement.condition } : {},
    )
  ]
}

resource "aws_s3_bucket_policy" "this" {
  count      = length(local.tls_statement) + length(local.grant_statements) > 0 ? 1 : 0
  bucket     = aws_s3_bucket.this.id
  depends_on = [aws_s3_bucket_public_access_block.this]
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.tls_statement, local.grant_statements)
  })
}
