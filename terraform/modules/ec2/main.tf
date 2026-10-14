data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

locals {
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id
  realistic  = contains(var.tiers, "realistic")

  ssm_core = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"

  # Scenarios in the selected tiers, keyed by scenario ID.
  scenarios = { for id, scenario in local.all_scenarios : id => scenario if contains(var.tiers, scenario.tier) }
}

# Shared security group that lets the monitoring stack scrape node exporters from inside the VPC.
resource "aws_security_group" "monitoring" {
  tags        = { Name = "${var.name}-node-exporter" }
  name        = "${var.name}-node-exporter"
  description = "Prometheus node exporter scraping from inside the VPC"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description = "Prometheus scrape"
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.prod_cidr]
  }
}

# Uploads bucket the image resizer reads from; it exists so the role points at a real bucket.
resource "aws_s3_bucket" "media" {
  bucket        = "${var.name}-media-uploads-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "media" {
  bucket                  = aws_s3_bucket.media.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "media" {
  bucket = aws_s3_bucket.media.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

module "scenario" {
  source        = "./instance"
  for_each      = toset(keys(local.scenarios))
  name          = "${var.name}-${local.scenarios[each.key].name}"
  config        = local.scenarios[each.key]
  ami           = data.aws_ssm_parameter.al2023.insecure_value
  instance_type = var.instance_type
  subnets       = local.subnets
}
