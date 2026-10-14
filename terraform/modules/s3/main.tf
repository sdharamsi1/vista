data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Scenarios in the selected tiers, keyed by scenario ID.
  scenarios = { for id, scenario in local.all_scenarios : id => scenario if contains(var.tiers, scenario.tier) }
}

# Shared target for server access logs; logging targets must use SSE-S3, not SSE-KMS.
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.name}-s3-access-logs-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  depends_on = [aws_s3_bucket_public_access_block.logs]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/*"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

module "scenario" {
  source     = "./bucket"
  for_each   = toset(keys(local.scenarios))
  name       = "${var.name}-${local.scenarios[each.key].name}-${local.account_id}"
  config     = local.scenarios[each.key]
  log_bucket = aws_s3_bucket.logs.id
}
