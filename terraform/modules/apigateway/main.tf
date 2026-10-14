data "aws_region" "current" {}
data "aws_partition" "current" {}
locals {
  region    = data.aws_region.current.region
  partition = data.aws_partition.current.partition

  # Scenarios in the selected tiers, keyed by scenario ID; REST APIs use the ./api module.
  scenarios      = { for id, scenario in local.all_scenarios : id => scenario if contains(var.tiers, scenario.tier) }
  rest_scenarios = { for id, scenario in local.scenarios : id => scenario if try(scenario.type, "REST") == "REST" }
  http_enabled   = contains(keys(local.scenarios), "apigw-09")
  cognito        = anytrue([for scenario in values(local.rest_scenarios) : try(scenario.authorization, "") == "COGNITO_USER_POOLS"])
}

# Customer identities for APIs that use a Cognito authorizer.
resource "aws_cognito_user_pool" "customers" {
  count                    = local.cognito ? 1 : 0
  name                     = "${var.name}-customers"
  deletion_protection      = "INACTIVE"
  auto_verified_attributes = ["email"]
  username_attributes      = ["email"]
  mfa_configuration        = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
}

# Backend for every REST API: routes call DynamoDB directly, so no Lambda code is needed.
resource "aws_dynamodb_table" "this" {
  name                        = "${var.name}-catalog-items"
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = false
  hash_key                    = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
# Execution and access logging need the account-wide CloudWatch role. This setting is per region
# and per account, so it replaces any role already configured there.
data "aws_iam_policy_document" "cloudwatch_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "cloudwatch" {
  name               = "${var.name}-apigateway-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_assume.json
}
resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.cloudwatch.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}
resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.cloudwatch.arn
  depends_on          = [aws_iam_role_policy_attachment.cloudwatch]
}
# Shared web ACL for every stage that has WAF: a per-IP rate limit and the common managed rules.
resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name}-apigateway"
  scope = "REGIONAL"
  default_action {
    allow {}
  }
  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "common-rules"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-common-rules"
      sampled_requests_enabled   = true
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-apigateway"
    sampled_requests_enabled   = true
  }
}
module "scenario" {
  source        = "./api"
  for_each      = toset(keys(local.rest_scenarios))
  name          = "${var.name}-${local.rest_scenarios[each.key].name}"
  config        = local.rest_scenarios[each.key]
  region        = local.region
  partition     = local.partition
  table_name    = aws_dynamodb_table.this.name
  table_arn     = aws_dynamodb_table.this.arn
  web_acl_arn   = aws_wafv2_web_acl.this.arn
  user_pool_arn = one(aws_cognito_user_pool.customers[*].arn)
  depends_on    = [aws_api_gateway_account.this]
}
