# API Gateway Security Review

## Account Risk Summary
Nine APIs were reviewed in us-east-1: eight REST APIs and one HTTP API (no WebSocket APIs, no custom domains, no VPC links). The dominant risk is unauthenticated invocation: six APIs expose routes with `authorization_type` NONE, several of which run AWS integration roles that call DynamoDB `Scan`, `PutItem`, and `DeleteItem` directly, and all APIs are reachable over their default execute-api endpoints (`disable_execute_api_endpoint` false).

## Top Findings

### 1. Unauthenticated read, write, and delete of DynamoDB data via brightpath-loyalty-points-api
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1)
- **Evidence:** All three routes (`DELETE /items`, `GET /items`, `PUT /items`) have `authorization_type` NONE, `api_key_required` false, and no authorizer; each uses `credentials_arn` arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration against `dynamodb:action/DeleteItem`, `Scan`, and `PutItem`. The API has no resource policy (`policy_ref` absent) and `disable_execute_api_endpoint` is false.
- **Why it matters:** Any internet caller can scan, overwrite, and delete items in the backing DynamoDB table using the integration role's permissions, with no caller identity recorded.
- **Remediation:** Attach an authorizer (e.g. the existing Cognito pattern) or set `authorization_type` to AWS_IAM on all three methods, and scope the integration role to the minimum table actions required; end state is no route on this API with `authorization_type` NONE.

### 2. Unauthenticated full-table read via brightpath-orders-api
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** `GET /items` has `authorization_type` NONE, `api_key_required` false, and integrates with `arn:aws:apigateway:us-east-1:dynamodb:action/Scan` using `credentials_arn` arn:aws:iam::111122223333:role/brightpath-orders-api-integration; no resource policy is present and `disable_execute_api_endpoint` is false.
- **Why it matters:** Anonymous callers can repeatedly scan the orders table contents through the public execute-api endpoint, limited only by the 25 rps / 50 burst stage throttle.
- **Remediation:** Require AWS_IAM or a Cognito/Lambda authorizer on `GET /items`; end state is that the route rejects unauthenticated requests.

### 3. Internal admin API relies on source-IP filtering instead of caller authentication
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use `authorization_type` NONE with `credentials_arn` arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration calling `dynamodb:action/DeleteItem` and `Scan`; resource policy pol-8796d633f8fa Allows Principal `*` and Denies only when `aws:SourceIp` is outside 203.0.113.0/24, and `disable_execute_api_endpoint` is false.
- **Why it matters:** Any client whose traffic originates from that /24 (shared NAT, compromised host, or any host in that range) can delete and scan admin data with no authenticated identity or per-caller attribution.
- **Remediation:** Add AWS_IAM or an authorizer to both methods and keep the IP condition as a second layer; end state is authenticated-and-IP-restricted admin access.

### 4. Unauthenticated HTTP API webhook route invoking a Lambda integration role
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `POST /webhooks/payments` has `authorization_type` NONE, `api_key_required` false, and no authorizers are defined on the API (`authorizers` is empty); it invokes AWS_PROXY integration `dxkligt` with `credentials_arn` arn:aws:iam::111122223333:role/brightpath-webhooks-integration, and `disable_execute_api_endpoint` is false on endpoint https://f76tda3ox7.execute-api.us-east-1.amazonaws.com.
- **Why it matters:** Anyone can submit arbitrary payment-webhook payloads to the backend function at up to 10 rps / 20 burst; no gateway-level request authentication exists (backend signature checking was not collected).
- **Remediation:** Add a JWT or Lambda authorizer (or IAM/mutual-TLS-fronted domain) to the route, or enforce provider signature validation before processing; end state is that only verifiable webhook senders are accepted.

### 5. Partner API protected only by an API key, not by caller authentication
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `authorization_type` NONE with `api_key_required` true, backed by `credentials_arn` arn:aws:iam::111122223333:role/brightpath-partner-api-integration calling DynamoDB `Scan` and `PutItem`; usage plan `vqo9fk` (20 burst / 10 rps, 100000/MONTH quota) has `api_key_count` 1.
- **Why it matters:** API keys are identifiers for throttling and quotas, not authentication, so anyone who obtains the single shared key can read and write the table with no further identity check.
- **Remediation:** Add AWS_IAM, a JWT, or a Lambda authorizer alongside the API key and issue per-partner keys; end state is authenticated partner calls with keys used only for quota attribution.

### 6. Full request and response bodies logged for brightpath-support-tickets-api
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage prod `method_settings` `*/*` sets `dataTraceEnabled` true with `loggingLevel` INFO, and the account has `cloudwatch_role_arn` arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch, so execution logs include full request and response payloads; all other APIs use `dataTraceEnabled` false.
- **Why it matters:** Ticket request/response contents, including any credentials or tokens in headers or bodies, are persisted in CloudWatch Logs where anyone with log read access can retrieve them.
- **Remediation:** Set `dataTraceEnabled` to false for the prod stage (keep `loggingLevel` ERROR/INFO without data tracing); end state is no payload logging in execution logs.

### 7. brightpath-reporting-api stage has throttling disabled and no WAF association
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage prod `method_settings` `*/*` sets `throttlingBurstLimit` -1 and `throttlingRateLimit` -1.0, and `web_acl_arn` is null, unlike the other seven REST APIs which use 50/25.0 and web ACL arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/1415ab8d-99c3-4cc5-be69-2a2e23b1dad4; no usage plan covers this stage.
- **Why it matters:** Traffic to this stage is bounded only by the shared regional account limit (10000 rps / 5000 burst), so a flood here can exhaust capacity for every API Gateway API in us-east-1.
- **Remediation:** Set explicit stage/method throttle limits on prod and associate the regional web ACL; end state is per-stage rate limiting independent of the account limit.

### 8. brightpath-inventory-api prod stage writes no access logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage prod has `access_log_destination` null while every other API stage points at a /aws/apigateway/* log group; the API's `GET /items` route uses AWS_IAM authorization and integration role arn:aws:iam::111122223333:role/brightpath-inventory-api-integration.
- **Why it matters:** No per-request record exists for this API, so misuse of the DynamoDB `Scan` integration cannot be investigated or attributed.
- **Remediation:** Configure `access_log_destination` to a CloudWatch Logs group with a format including caller identity and source IP; end state is access logging enabled on the prod stage.
