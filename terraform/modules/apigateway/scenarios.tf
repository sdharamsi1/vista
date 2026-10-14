# Expected ratings are in ground-truth.json. Every REST API starts hardened (IAM authorization,
# request validation, WAF, stage throttling, access and execution logging) and lists only what
# differs. apigw-09 is an HTTP API defined in http.tf.
#
# controlled: the single-flaw severity ladder.
# realistic:  expected, ambiguous, and messy cases, including an HTTP API.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # LOW: IAM-authenticated, but the stage has no access logging.
    "apigw-01" = {
      tier        = "controlled"
      name        = "inventory-api"
      access_logs = false
    }
    # MEDIUM: IAM-authenticated, but execution logging records full request and response bodies.
    "apigw-02" = {
      tier       = "controlled"
      name       = "support-tickets-api"
      data_trace = true
    }
    # MEDIUM: IAM-authenticated, but the stage has no WAF and no throttling.
    "apigw-03" = {
      tier       = "controlled"
      name       = "reporting-api"
      waf        = false
      throttling = false
    }
    # HIGH: anyone on the Internet can read every item in the table, with no authorization.
    "apigw-04" = {
      tier          = "controlled"
      name          = "orders-api"
      authorization = "NONE"
    }
    # CRITICAL: anyone on the Internet can read, write, and delete items, with no authorization.
    "apigw-05" = {
      tier          = "controlled"
      name          = "loyalty-points-api"
      authorization = "NONE"
      methods       = ["GET", "PUT", "DELETE"]
    }

    # ---------- realistic ----------

    # EXPECTED: customer API behind a Cognito authorizer, plus an anonymous MOCK /health check.
    "apigw-06" = {
      tier          = "realistic"
      name          = "customer-api"
      authorization = "COGNITO_USER_POOLS"
      methods       = ["GET", "PUT"]
      health_route  = true
    }
    # HIGH: partner API "secured" only by an API key, which identifies callers but does not
    # authenticate them; the key can read and write items.
    "apigw-07" = {
      tier             = "realistic"
      name             = "partner-api"
      authorization    = "NONE"
      api_key_required = true
      usage_plan       = true
      methods          = ["GET", "PUT"]
    }
    # AMBIGUOUS: internal admin API with no authorization, restricted only to the office IP range
    # by a resource policy; it can delete items.
    "apigw-08" = {
      tier                 = "realistic"
      name                 = "internal-admin-api"
      authorization        = "NONE"
      allowed_source_cidrs = [var.office_cidr]
      methods              = ["GET", "DELETE"]
    }
    # AMBIGUOUS: HTTP API for payment-provider webhooks. POST /webhooks/payments has no
    # authorization and writes straight to SQS; signature checks would happen downstream.
    "apigw-09" = {
      tier = "realistic"
      name = "webhooks"
      type = "HTTP"
    }
  }
}
