# ground-truth.json is the facts-only answer key: each scenario's condition, FSBP coverage, and
# published FSBP control severities. Every REST API starts from the module's hardened default (IAM
# authorization, request validation, WAF, stage throttling, access and execution logging) and lists
# only what differs. apigw-09 is an HTTP API defined in http.tf.
#
# controlled: one setting changed per API from that default.
# realistic:  APIs with Cognito, API key, and resource policy configurations, and an HTTP API.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # IAM authorization; the stage has no access logging.
    "apigw-01" = {
      tier        = "controlled"
      name        = "inventory-api"
      access_logs = false
    }
    # IAM authorization; execution logging with data tracing records full request and response bodies.
    "apigw-02" = {
      tier       = "controlled"
      name       = "support-tickets-api"
      data_trace = true
    }
    # IAM authorization; the stage has no WAF web ACL and no stage throttle.
    "apigw-03" = {
      tier       = "controlled"
      name       = "reporting-api"
      waf        = false
      throttling = false
    }
    # GET /items has authorization NONE and calls DynamoDB Scan on the shared table.
    "apigw-04" = {
      tier          = "controlled"
      name          = "orders-api"
      authorization = "NONE"
    }
    # GET, PUT, and DELETE /items have authorization NONE and call Scan, PutItem, and DeleteItem.
    "apigw-05" = {
      tier          = "controlled"
      name          = "loyalty-points-api"
      authorization = "NONE"
      methods       = ["GET", "PUT", "DELETE"]
    }

    # ---------- realistic ----------

    # Customer API with a Cognito authorizer on /items, plus GET /health with authorization NONE and
    # a MOCK integration.
    "apigw-06" = {
      tier          = "realistic"
      name          = "customer-api"
      authorization = "COGNITO_USER_POOLS"
      methods       = ["GET", "PUT"]
      health_route  = true
    }
    # Partner API whose GET and PUT /items routes have authorization NONE and api_key_required true,
    # with a usage plan and one API key.
    "apigw-07" = {
      tier             = "realistic"
      name             = "partner-api"
      authorization    = "NONE"
      api_key_required = true
      usage_plan       = true
      methods          = ["GET", "PUT"]
    }
    # Admin API whose GET and DELETE /items routes have authorization NONE; the resource policy denies
    # requests whose source IP is outside the office CIDR.
    "apigw-08" = {
      tier                 = "realistic"
      name                 = "internal-admin-api"
      authorization        = "NONE"
      allowed_source_cidrs = [var.office_cidr]
      methods              = ["GET", "DELETE"]
    }
    # HTTP API for payment-provider webhooks. POST /webhooks/payments has authorization NONE and
    # sends the request body to SQS.
    "apigw-09" = {
      tier = "realistic"
      name = "webhooks"
      type = "HTTP"
    }
  }
}
