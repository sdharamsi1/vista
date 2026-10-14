# One scenario REST API: regional, IAM-authenticated, request-validated, behind WAF, throttled, and
# logged, unless config says otherwise. Each /items route calls one DynamoDB action with a role
# limited to exactly those actions on the shared table.
locals {
  # Route -> the DynamoDB action it invokes and the request template that builds the call.
  routes = {
    GET = {
      action   = "Scan"
      iam      = "dynamodb:Scan"
      template = "{\"TableName\":\"${var.table_name}\"}"
    }
    PUT = {
      action   = "PutItem"
      iam      = "dynamodb:PutItem"
      template = "{\"TableName\":\"${var.table_name}\",\"Item\":{\"id\":{\"S\":\"$input.path('$.id')\"}}}"
    }
    DELETE = {
      action   = "DeleteItem"
      iam      = "dynamodb:DeleteItem"
      template = "{\"TableName\":\"${var.table_name}\",\"Key\":{\"id\":{\"S\":\"$input.params('id')\"}}}"
    }
  }
  active  = { for method in var.config.methods : method => local.routes[method] }
  stage   = "prod"
  cognito = var.config.authorization == "COGNITO_USER_POOLS"
}

resource "aws_api_gateway_rest_api" "this" {
  name = var.name
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# IP allowlist: allow invoke from the listed CIDRs and explicitly deny everyone else.
resource "aws_api_gateway_rest_api_policy" "this" {
  count       = length(var.config.allowed_source_cidrs) > 0 ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.this.execution_arn}/*"
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.this.execution_arn}/*"
        Condition = { NotIpAddress = { "aws:SourceIp" = var.config.allowed_source_cidrs } }
      },
    ]
  })
}

resource "aws_api_gateway_authorizer" "cognito" {
  count           = local.cognito ? 1 : 0
  name            = "cognito-users"
  rest_api_id     = aws_api_gateway_rest_api.this.id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = [var.user_pool_arn]
  identity_source = "method.request.header.Authorization"
}

resource "aws_api_gateway_request_validator" "this" {
  rest_api_id                 = aws_api_gateway_rest_api.this.id
  name                        = "body-and-parameters"
  validate_request_body       = true
  validate_request_parameters = true
}

resource "aws_api_gateway_model" "item" {
  rest_api_id  = aws_api_gateway_rest_api.this.id
  name         = "Item"
  content_type = "application/json"
  schema = jsonencode({
    "$schema"            = "http://json-schema.org/draft-04/schema#"
    type                 = "object"
    required             = ["id"]
    additionalProperties = false
    properties           = { id = { type = "string", maxLength = 64 } }
  })
}

resource "aws_api_gateway_resource" "items" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "items"
}

# Execution role: only the DynamoDB actions the routes use, on the one table.
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "integration" {
  name               = "${var.name}-integration"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "integration" {
  name = "permissions"
  role = aws_iam_role.integration.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [for route in local.active : route.iam]
      Resource = var.table_arn
    }]
  })
}

resource "aws_api_gateway_method" "this" {
  for_each             = local.active
  rest_api_id          = aws_api_gateway_rest_api.this.id
  resource_id          = aws_api_gateway_resource.items.id
  http_method          = each.key
  authorization        = var.config.authorization
  authorizer_id        = local.cognito ? aws_api_gateway_authorizer.cognito[0].id : null
  api_key_required     = var.config.api_key_required
  request_validator_id = aws_api_gateway_request_validator.this.id
  request_models       = each.key == "PUT" ? { "application/json" = aws_api_gateway_model.item.name } : null
  request_parameters   = each.key == "DELETE" ? { "method.request.querystring.id" = true } : null
}

resource "aws_api_gateway_integration" "this" {
  for_each                = local.active
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = aws_api_gateway_resource.items.id
  http_method             = aws_api_gateway_method.this[each.key].http_method
  type                    = "AWS"
  integration_http_method = "POST"
  uri                     = "arn:${var.partition}:apigateway:${var.region}:dynamodb:action/${each.value.action}"
  credentials             = aws_iam_role.integration.arn
  request_templates       = { "application/json" = each.value.template }
  depends_on              = [aws_iam_role_policy.integration]
}

resource "aws_api_gateway_method_response" "this" {
  for_each    = local.active
  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.items.id
  http_method = aws_api_gateway_method.this[each.key].http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "this" {
  for_each    = local.active
  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.items.id
  http_method = aws_api_gateway_method.this[each.key].http_method
  status_code = aws_api_gateway_method_response.this[each.key].status_code
  depends_on  = [aws_api_gateway_integration.this]
}

# ---------- Optional anonymous GET /health backed by a MOCK integration ----------

resource "aws_api_gateway_resource" "health" {
  count       = var.config.health_route ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "health"
}

resource "aws_api_gateway_method" "health" {
  count         = var.config.health_route ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = aws_api_gateway_resource.health[0].id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health" {
  count             = var.config.health_route ? 1 : 0
  rest_api_id       = aws_api_gateway_rest_api.this.id
  resource_id       = aws_api_gateway_resource.health[0].id
  http_method       = aws_api_gateway_method.health[0].http_method
  type              = "MOCK"
  request_templates = { "application/json" = "{\"statusCode\": 200}" }
}

resource "aws_api_gateway_method_response" "health" {
  count       = var.config.health_route ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.this.id
  resource_id = aws_api_gateway_resource.health[0].id
  http_method = aws_api_gateway_method.health[0].http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "health" {
  count              = var.config.health_route ? 1 : 0
  rest_api_id        = aws_api_gateway_rest_api.this.id
  resource_id        = aws_api_gateway_resource.health[0].id
  http_method        = aws_api_gateway_method.health[0].http_method
  status_code        = aws_api_gateway_method_response.health[0].status_code
  response_templates = { "application/json" = "{\"status\": \"ok\"}" }
  depends_on         = [aws_api_gateway_integration.health]
}

# ---------- Deployment, stage, and stage protections ----------

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.items.id,
      [for method in aws_api_gateway_method.this : method.id],
      [for integration in aws_api_gateway_integration.this : integration.id],
      aws_api_gateway_method.health[*].id,
      aws_api_gateway_integration.health[*].id,
      aws_api_gateway_authorizer.cognito[*].id,
      aws_api_gateway_rest_api_policy.this[*].policy,
      aws_api_gateway_request_validator.this.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_api_gateway_integration_response.this,
    aws_api_gateway_integration_response.health,
    aws_api_gateway_rest_api_policy.this,
  ]
}

# Log groups are created up front so terraform destroy removes them with the API.
resource "aws_cloudwatch_log_group" "access" {
  count             = var.config.access_logs ? 1 : 0
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "execution" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.this.id}/${local.stage}"
  retention_in_days = 7
}

resource "aws_api_gateway_stage" "this" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = local.stage
  dynamic "access_log_settings" {
    for_each = var.config.access_logs ? [1] : []
    content {
      destination_arn = aws_cloudwatch_log_group.access[0].arn
      format = jsonencode({
        requestId      = "$context.requestId"
        requestTime    = "$context.requestTime"
        sourceIp       = "$context.identity.sourceIp"
        caller         = "$context.identity.caller"
        apiKeyId       = "$context.identity.apiKeyId"
        httpMethod     = "$context.httpMethod"
        resourcePath   = "$context.resourcePath"
        status         = "$context.status"
        responseLength = "$context.responseLength"
      })
    }
  }
  depends_on = [aws_cloudwatch_log_group.execution]
}

resource "aws_wafv2_web_acl_association" "this" {
  count        = var.config.waf ? 1 : 0
  resource_arn = aws_api_gateway_stage.this.arn
  web_acl_arn  = var.web_acl_arn
}

# A rate and burst of -1 means no stage-level throttle, leaving only the account limit.
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"
  settings {
    metrics_enabled        = true
    logging_level          = var.config.data_trace ? "INFO" : "ERROR"
    data_trace_enabled     = var.config.data_trace
    throttling_burst_limit = var.config.throttling ? 50 : -1
    throttling_rate_limit  = var.config.throttling ? 25 : -1
  }
}

# ---------- Optional usage plan with one API key for a partner ----------

resource "aws_api_gateway_usage_plan" "this" {
  count = var.config.usage_plan ? 1 : 0
  name  = "${var.name}-partners"

  api_stages {
    api_id = aws_api_gateway_rest_api.this.id
    stage  = aws_api_gateway_stage.this.stage_name
  }
  throttle_settings {
    burst_limit = 20
    rate_limit  = 10
  }
  quota_settings {
    limit  = 100000
    period = "MONTH"
  }
}

resource "aws_api_gateway_api_key" "this" {
  count = var.config.usage_plan ? 1 : 0
  name  = "${var.name}-partner-key"
}

resource "aws_api_gateway_usage_plan_key" "this" {
  count         = var.config.usage_plan ? 1 : 0
  key_id        = aws_api_gateway_api_key.this[0].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.this[0].id
}
