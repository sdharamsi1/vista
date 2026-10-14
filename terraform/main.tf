# Ground-truth scenarios for evaluating Vista. Many are deliberately insecure: deploy only to a
# sandbox account, scan, then `terraform destroy`. Nothing has deletion protection, buckets are
# force-destroyed, and databases skip their final snapshot, so one destroy removes everything.
#
# Resource names never contain scenario IDs; terraform output scenario_resources maps each ID to
# the identifier Vista cites, and each module's ground-truth.json holds the expected ratings.
module "ec2" {
  source      = "./modules/ec2"
  count       = var.enable_ec2 ? 1 : 0
  name        = var.name
  tiers       = var.tiers
  office_cidr = var.office_cidr
}

module "s3" {
  source = "./modules/s3"
  count  = var.enable_s3 ? 1 : 0
  name   = var.name
  tiers  = var.tiers
}

module "apigateway" {
  source      = "./modules/apigateway"
  count       = var.enable_apigateway ? 1 : 0
  name        = var.name
  tiers       = var.tiers
  office_cidr = var.office_cidr
}

module "rds" {
  source      = "./modules/rds"
  count       = var.enable_rds ? 1 : 0
  name        = var.name
  tiers       = var.tiers
  office_cidr = var.office_cidr
}
