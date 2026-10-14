# apigw-09: HTTP API that accepts payment-provider webhooks with no authorization and writes the
# body straight to an SQS queue through a first-class integration. Access logging and route
# throttling are on; HTTP APIs cannot attach WAF.

resource "aws_sqs_queue" "webhooks" {
  count                   = local.http_enabled ? 1 : 0
  name                    = "${var.name}-payment-webhooks"
  sqs_managed_sse_enabled = true
}

resource "aws_iam_role" "webhooks" {
  count              = local.http_enabled ? 1 : 0
  name               = "${var.name}-webhooks-integration"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_assume.json
}

resource "aws_iam_role_policy" "webhooks" {
  count = local.http_enabled ? 1 : 0
  name  = "send-to-queue"
  role  = aws_iam_role.webhooks[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.webhooks[0].arn
    }]
  })
}

resource "aws_apigatewayv2_api" "webhooks" {
  count         = local.http_enabled ? 1 : 0
  name          = "${var.name}-${local.all_scenarios["apigw-09"].name}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "webhooks" {
  count                  = local.http_enabled ? 1 : 0
  api_id                 = aws_apigatewayv2_api.webhooks[0].id
  integration_type       = "AWS_PROXY"
  integration_subtype    = "SQS-SendMessage"
  credentials_arn        = aws_iam_role.webhooks[0].arn
  payload_format_version = "1.0"
  request_parameters = {
    QueueUrl    = aws_sqs_queue.webhooks[0].url
    MessageBody = "$request.body"
  }
  depends_on = [aws_iam_role_policy.webhooks]
}

resource "aws_apigatewayv2_route" "webhooks" {
  count              = local.http_enabled ? 1 : 0
  api_id             = aws_apigatewayv2_api.webhooks[0].id
  route_key          = "POST /webhooks/payments"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.webhooks[0].id}"
}

resource "aws_cloudwatch_log_group" "webhooks" {
  count             = local.http_enabled ? 1 : 0
  name              = "/aws/apigateway/${aws_apigatewayv2_api.webhooks[0].name}"
  retention_in_days = 7
}

resource "aws_apigatewayv2_stage" "webhooks" {
  count       = local.http_enabled ? 1 : 0
  api_id      = aws_apigatewayv2_api.webhooks[0].id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.webhooks[0].arn
    format = jsonencode({
      requestId = "$context.requestId"
      sourceIp  = "$context.identity.sourceIp"
      routeKey  = "$context.routeKey"
      status    = "$context.status"
    })
  }
}
