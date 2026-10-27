# API Gateway Security Review

## Account Risk Summary
Nine APIs were reviewed in a single region (us-east-1): eight REST APIs and one HTTP API, with no WebSocket APIs. Posture is uneven — several production REST routes and the payments webhook route enforce no caller authentication (`authorization_type` NONE) while running with integration IAM roles against DynamoDB, and one API relies solely on an IP-based resource policy; the remaining APIs use AWS_IAM or Cognito and are comparatively sound.

## Top Findings

### 1. Unauthenticated REST routes write, delete, and scan DynamoDB with an integration IAM role
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** On `2jhbfrn3v6`, all three routes (`DELETE /items`, `GET /items`, `PUT /items`) have `authorization_type` NONE, `api_key_required` false, no authorizers defined, and integrations calling `dynamodb:action/DeleteItem`, `Scan`, and `PutItem` with `credentials_arn` arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration; `q4ozo3nsg6` route `GET /items` is identical with `dynamodb:action/Scan` and role brightpath-orders-api-integration. Both APIs have no resource policy and `disable_execute_api_endpoint` false, so the default execute-api endpoint is reachable by any Internet caller.
- **Why it matters:** Any anonymous caller can read entire tables via Scan and, on the loyalty API, create and delete items using the integration role's DynamoDB permissions on every request.
- **Remediation:** Set `authorization_type` to AWS_IAM or attach a Cognito/JWT authorizer (as done on `9abf9333md` with authorizer `gdgqeq`) on every route of `2jhbfrn3v6` and `q4ozo3nsg6`, and scope each integration role to the minimum DynamoDB actions and table ARNs.

### 2. Payments webhook HTTP route accepts unauthenticated requests
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** Route `POST /webhooks/payments` has `authorization_type` NONE, `api_key_required` false, and the API defines no authorizers; it maps to integration `dxkligt` (type AWS_PROXY, `credentials_arn` arn:aws:iam::111122223333:role/brightpath-webhooks-integration). `disable_execute_api_endpoint` is false on endpoint https://f76tda3ox7.execute-api.us-east-1.amazonaws.com, and the `$default` stage only caps traffic at ThrottlingRateLimit 10.0 / burst 20; HTTP APIs cannot be associated with a WAF web ACL.
- **Why it matters:** Anyone on the Internet can submit arbitrary payment-webhook payloads that are processed with the integration role's permissions, with no gateway-level caller verification.
- **Remediation:** Attach a JWT or Lambda authorizer to `POST /webhooks/payments` (or require a provider signature validated before any state change) so unauthenticated invocations are rejected at the gateway; the integration target and its signature handling were not collected and should be confirmed.

### 3. Partner API relies on an API key alone for access control
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** Routes `GET /items` and `PUT /items` have `authorization_type` NONE with `api_key_required` true and `api_key_source` HEADER; the integrations call `dynamodb:action/Scan` and `dynamodb:action/PutItem` with `credentials_arn` arn:aws:iam::111122223333:role/brightpath-partner-api-integration. Usage plan `vqo9fk` holds a single API key with throttle 10.0/burst 20 and a 100,000-request monthly quota, and the API has no resource policy.
- **Why it matters:** API keys identify clients for throttling and quotas rather than authenticating them, so possession of the one header value grants table reads and writes through the integration role.
- **Remediation:** Add a real authorizer (AWS_IAM, Cognito, or Lambda) to both partner routes and keep the API key only for usage-plan metering and quota enforcement.

### 4. Internal admin API has no authentication and is gated only by a source-IP resource policy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** Routes `DELETE /items` and `GET /items` have `authorization_type` NONE and no authorizers, backed by `dynamodb:action/DeleteItem` and `Scan` with `credentials_arn` arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration. Resource policy `pol-8796d633f8fa` allows Principal "*" and denies only requests where `aws:SourceIp` is outside 203.0.113.0/24; `disable_execute_api_endpoint` is false.
- **Why it matters:** Any client whose requests originate from the 203.0.113.0/24 range — including shared egress or a compromised host in that range — can scan and delete table items as an unauthenticated caller of an admin API.
- **Remediation:** Require `authorization_type` AWS_IAM (or an authorizer) on both routes and keep the IP Deny statement as a secondary network control rather than the sole access gate.

### 5. Full request and response bodies written to execution logs for the support tickets API
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage prod `method_settings` `*/*` has `dataTraceEnabled` true with `loggingLevel` INFO, and account_settings for us-east-1 supplies `cloudwatch_role_arn` arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch, so execution logging is active; all other APIs in the account use `dataTraceEnabled` false.
- **Why it matters:** Every request and response body for the ticket API, including any credentials or personal data clients send, is persisted in CloudWatch Logs where any principal with log read access can retrieve it.
- **Remediation:** Set `dataTraceEnabled` to false on stage prod of `7l3cra87nl` (keep `loggingLevel` ERROR/INFO without data tracing) so payload bodies are no longer logged.

### 6. Reporting API stage has throttling disabled and no WAF web ACL
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage prod `method_settings` `*/*` sets `throttlingBurstLimit` -1 and `throttlingRateLimit` -1.0 (no method/stage limit) and `web_acl_arn` is null, while the other seven REST APIs use 25.0/50 limits and web ACL arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/1415ab8d-99c3-4cc5-be69-2a2e23b1dad4. Its `GET /items` route (DynamoDB Scan via role brightpath-reporting-api-integration) is then bounded only by the region's account limit of rateLimit 10000.0 / burstLimit 5000.
- **Why it matters:** A single IAM-authorized caller issuing expensive Scan requests can consume the shared regional account quota and degrade every other API Gateway API in us-east-1.
- **Remediation:** Set explicit stage or method throttle limits on prod of `14gn38be16` and associate the existing regional web ACL, matching the other REST stages.

### 7. Inventory API stage writes no access logs
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage prod has `access_log_destination` null, while all other REST stages (for example `/aws/apigateway/brightpath-orders-api`) have a log group configured; its `GET /items` route is AWS_IAM-authorized and backed by `dynamodb:action/Scan` with role brightpath-inventory-api-integration.
- **Why it matters:** No per-request record exists for this API, so misuse of the DynamoDB Scan route cannot be detected or investigated from API Gateway logs.
- **Remediation:** Set `access_log_destination` on stage prod of `qijacgncdf` to a CloudWatch Logs group with a format that includes caller identity, source IP, route, and status.
