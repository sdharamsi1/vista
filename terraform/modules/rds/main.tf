data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id

  # Scenarios in the selected tiers, keyed by scenario ID; DB instances use the ./instance module.
  scenarios    = { for id, scenario in local.all_scenarios : id => scenario if contains(var.tiers, scenario.tier) }
  db_scenarios = { for id, scenario in local.scenarios : id => scenario if try(scenario.type, "INSTANCE") == "INSTANCE" }
  # rds-07 (the proxy) and its target rds-06 are both realistic. Keyed off var.tiers directly,
  # because the scenario map itself references the proxy security group.
  proxy_target  = "rds-06"
  proxy_enabled = contains(var.tiers, "realistic")

  engines = {
    postgres = {
      version = data.aws_rds_engine_version.this.version
      family  = data.aws_rds_engine_version.this.parameter_group_family
    }
    mysql = {
      version = data.aws_rds_engine_version.mysql.version
      family  = data.aws_rds_engine_version.mysql.parameter_group_family
    }
  }
}

# Customer-managed key shared by every encrypted scenario, so none of them trips the AWS-managed key check.
resource "aws_kms_key" "this" {
  description             = "${var.name} databases"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

# Export target for the events database's s3Export role; it exists so the role points at a real bucket.
resource "aws_s3_bucket" "exports" {
  bucket        = "${var.name}-db-exports-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

module "scenario" {
  source               = "./instance"
  for_each             = toset(keys(local.db_scenarios))
  name                 = "${var.name}-${local.db_scenarios[each.key].name}"
  config               = local.db_scenarios[each.key]
  engines              = local.engines
  instance_class       = var.instance_class
  vpc_id               = aws_vpc.this.id
  public_subnet_group  = aws_db_subnet_group.public.name
  private_subnet_group = aws_db_subnet_group.private.name
  kms_key_arn          = aws_kms_key.this.arn
}
