# API Gateway Security Review

## Account Risk Summary
Nine APIs were reviewed in us-east-1 (eight REST, one HTTP, no WebSocket), all backed by AWS service integrations that run with an IAM role. The dominant risk is unauthenticated invocation: five APIs expose routes with `authorization_type` NONE, including DynamoDB `PutItem`/`DeleteItem`/`Scan` actions, and only one REST API (`9abf9333md`) enforces a Cognito authorizer on its data routes.

## Top Findings

### 1. Unauthenticated read, write, and delete of DynamoDB data via brightpath-loyalty-points-api
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1)
- **Evidence:** All three routes (`DELETE /items`, `GET /items`, `PUT /items`) have `authorization_type` NONE, no `authorizer_id`, and `api_key_required` false; each integration calls `arn:aws:apigateway:us-east-1:dynamodb:action/DeleteItem`, `Scan`, and `PutItem` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration`. The API has no `policy_ref` (no resource policy) and `disable_execute_api_endpoint` is false, so the execute-api endpoint is reachable by any caller.
- **Why it matters:** Any internet caller can scan the entire backing table, insert items, and delete items using the integration role's DynamoDB permissions, with no caller identity recorded.
- **Remediation:** Set an authorizer on every route (e.g. `authorization_type` AWS_IAM or the Cognito pattern used by `9abf9333md`) so no route remains at NONE, and scope the integration role to only the required DynamoDB actions and table.

### 2. Admin delete/scan API protected only by an IP allowlist, with no caller authentication
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` are `authorization_type` NONE with no authorizers defined; resource policy `pol-8796d633f8fa` allows `execute-api:Invoke` for Principal `*` on `ht89xxg270/*` and denies only when `aws:SourceIp` is not in `203.0.113.0/24`. Integrations use `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration` for DynamoDB `DeleteItem` and `Scan`.
- **Why it matters:** Any host that can source traffic from 203.0.113.0/24 (shared office/VPN egress, a compromised host in that range) gets unauthenticated administrative scan and delete against the backing table.
- **Remediation:** Add an authorizer (AWS_IAM or Cognito/JWT) to both routes so identity is required in addition to the `aws:SourceIp` Deny, keeping the IP condition as a second layer.

### 3. Unauthenticated public HTTP API invoking a credentialed Lambda proxy integration
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** Route `POST /webhooks/payments` has `authorization_type` NONE, no `authorizer_id`, `api_key_required` false, and `authorizers` is empty; integration `dxkligt` is `AWS_PROXY` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-webhooks-integration`. `disable_execute_api_endpoint` is false at `https://f76tda3ox7.execute-api.us-east-1.amazonaws.com`, and HTTP APIs cannot be associated with a WAF web ACL; only `$default` stage throttling (rate 10, burst 20) limits volume.
- **Why it matters:** Anyone on the internet can submit arbitrary payment-webhook payloads that are processed with the integration role's permissions; no API Gateway layer authenticates the sender.
- **Confidence note:** Backend code behind the integration was not collected, so any in-code signature verification is unknown.
- **Remediation:** Attach a JWT or Lambda authorizer to `POST /webhooks/payments` (or require a provider signature validated before business logic) so unauthenticated requests are rejected at the API.

### 4. Unauthenticated full-table scan exposed by brightpath-orders-api
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** `GET /items` has `authorization_type` NONE, no `authorizer_id`, `api_key_required` false, and no `policy_ref`; the integration calls `arn:aws:apigateway:us-east-1:dynamodb:action/Scan` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-orders-api-integration`. `disable_execute_api_endpoint` is false.
- **Why it matters:** Any internet caller can repeatedly scan the orders table contents through the API's own IAM role, bounded only by the stage throttle of 25 rps / 50 burst.
- **Remediation:** Require an authorizer (AWS_IAM, Cognito, or JWT) on `GET /items` and replace the open `Scan` integration with a key-scoped query so unauthenticated bulk reads are impossible.

### 5. API key is the only access control on brightpath-partner-api write route
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` are `authorization_type` NONE with `api_key_required` true and no authorizers; usage plan `vqo9fk` attaches stage `prod` with 1 API key, throttle 10 rps / 20 burst, and a 100,000/MONTH quota. Integrations use `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-partner-api-integration` for DynamoDB `Scan` and `PutItem`.
- **Why it matters:** API keys identify clients for throttling, not authentication; a single leaked key grants full table scan and item writes with no further identity check.
- **Remediation:** Add an authorizer (AWS_IAM signing or a JWT/Cognito authorizer) to both routes and keep the API key only for usage-plan metering.

### 6. Full request and response bodies written to CloudWatch execution logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage `prod` `method_settings` `*/*` has `dataTraceEnabled` true with `loggingLevel` INFO, and `account_settings` for us-east-1 supplies `cloudwatch_role_arn` `arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch`, so execution logging is active. No other API in the account has `dataTraceEnabled` true.
- **Why it matters:** Every support-ticket request and response payload is persisted in CloudWatch Logs, widening exposure of that content to anyone with log read access and to log retention policy.
- **Remediation:** Set `dataTraceEnabled` to false on the `prod` stage (keep `loggingLevel` ERROR/INFO without data tracing) so payload bodies are no longer logged.

### 7. Reporting API stage has throttling disabled and no WAF association
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage `prod` `method_settings` `*/*` sets `throttlingBurstLimit` -1 and `throttlingRateLimit` -1.0 (no method/stage limit) and `web_acl_arn` is null, unlike the other seven REST APIs which share `arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/...` and 25 rps / 50 burst. The route's integration is a DynamoDB `Scan` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-reporting-api-integration`.
- **Why it matters:** Traffic to this API is bounded only by the shared regional account limit (10000 rps / 5000 burst), so a flood here can consume capacity for every API Gateway API in us-east-1 and drive unbounded DynamoDB `Scan` cost.
- **Remediation:** Set positive `throttlingRateLimit`/`throttlingBurstLimit` values on the `prod` stage and associate the existing regional web ACL with the stage.

### 8. Inventory API stage writes no access logs
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage `prod` has `access_log_destination` null, while every other REST stage logs to `/aws/apigateway/<api-name>`; the stage also has `tracing_enabled` false and `loggingLevel` ERROR only.
- **Why it matters:** Requests to this AWS_IAM-protected DynamoDB `Scan` route leave no per-request record, so misuse or abuse of the route cannot be reconstructed.
- **Remediation:** Set `access_log_destination` on the `prod` stage to a CloudWatch log group with a request-level format, matching the other APIs in the account.
