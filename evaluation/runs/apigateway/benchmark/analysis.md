# API Gateway Security Review

## Account Risk Summary
Nine APIs were reviewed in us-east-1 (eight REST, one HTTP, no WebSocket); all are reachable over their default execute-api endpoints (`disable_execute_api_endpoint` false) and no custom domains exist. Four APIs expose routes with `authorization_type` NONE and no authorizer, including unauthenticated DynamoDB write/delete paths that run under integration IAM roles, which is the account's dominant risk; the remainder of the posture (WAF on most stages, request validators, access logs) is largely consistent.

## Top Findings

### 1. Unauthenticated write and delete routes on brightpath-loyalty-points-api
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1)
- **Evidence:** All three routes (`DELETE /items`, `PUT /items`, `GET /items`) have `authorization_type` NONE, `authorizer_id` null, and `api_key_required` false; each integration calls DynamoDB actions `DeleteItem`, `PutItem`, and `Scan` using `credentials_arn` arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration. The API has no `policy_ref` (no resource policy) and `disable_execute_api_endpoint` is false, so the stage `prod` is callable by anyone on the internet.
- **Why it matters:** Any anonymous caller can read, overwrite, and delete records through the integration role's DynamoDB permissions, giving unauthenticated data destruction and tampering.
- **Remediation:** Attach an authorizer (e.g. the existing Cognito pattern) or set `authorization_type` to AWS_IAM on all three methods, and scope the integration role to only the required table and actions; end state is no route with `authorization_type` NONE on this API.

### 2. Admin delete/scan API authenticated only by a source-IP resource policy
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use `authorization_type` NONE with `authorizer_id` null; resource policy pol-8796d633f8fa allows `execute-api:Invoke` for Principal `*` and denies only when `aws:SourceIp` is outside 203.0.113.0/24. Integrations run DynamoDB `DeleteItem` and `Scan` as arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration.
- **Why it matters:** Any caller whose traffic originates from the 203.0.113.0/24 range — including any compromised host, shared NAT, or proxy in that range — can delete and dump data with no caller identity recorded or required.
- **Remediation:** Add AWS_IAM or a Cognito/Lambda authorizer to both methods while keeping the IP Deny as a second layer; end state is identity-based authorization plus the network condition.

### 3. Unauthenticated routes on brightpath-orders-api and brightpath-webhooks
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `q4ozo3nsg6` (brightpath-orders-api, us-east-1), `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `q4ozo3nsg6` route `GET /items` has `authorization_type` NONE, `api_key_required` false, no resource policy, and an AWS integration to DynamoDB `action/Scan` with `credentials_arn` .../brightpath-orders-api-integration. HTTP API `f76tda3ox7` route `POST /webhooks/payments` has `authorization_type` NONE and no authorizers defined, invoking AWS_PROXY integration dxkligt with `credentials_arn` .../brightpath-webhooks-integration at https://f76tda3ox7.execute-api.us-east-1.amazonaws.com.
- **Why it matters:** Anyone on the internet can scan the orders data set and submit arbitrary payment-webhook payloads into the backend Lambda, with API Gateway performing no caller authentication (HTTP APIs also cannot be fronted by WAF).
- **Remediation:** Set AWS_IAM (orders) and a JWT or Lambda authorizer (webhooks, or request-signature verification enforced at the route) so no route remains `authorization_type` NONE; evidence of in-Lambda signature validation was not collected.

### 4. Partner API relies on an API key instead of caller authentication
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `authorization_type` NONE with `api_key_required` true (`api_key_source` HEADER); usage plan vqo9fk covers stage prod with 1 API key, 10 rps/20 burst, and 100000/MONTH quota. Integrations use `credentials_arn` .../brightpath-partner-api-integration for DynamoDB `Scan` and `PutItem`.
- **Why it matters:** API keys identify clients for throttling only, so possession of the single distributed key grants anonymous read and write access to the DynamoDB-backed data through the integration role.
- **Remediation:** Add an authorizer or AWS_IAM authorization to both methods and keep the API key solely for usage-plan metering; end state is authenticated callers with the key as a secondary identifier.

### 5. Full request and response bodies written to CloudWatch execution logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage `prod` method settings `*/*` have `dataTraceEnabled` true with `loggingLevel` INFO, and the region has `cloudwatch_role_arn` arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch, so execution logging is active for every method.
- **Why it matters:** Every request and response body for this ticketing API, including any credentials or personal content callers submit, is persisted in CloudWatch Logs where any principal with log read access can retrieve it.
- **Remediation:** Set `dataTraceEnabled` to false (and reduce `loggingLevel` to ERROR) on the `*/*` method setting; end state is no payload logging on production stages.

### 6. Reporting API stage has throttling disabled, exposing the shared account limit
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage `prod` method settings `*/*` set `throttlingBurstLimit` -1 and `throttlingRateLimit` -1.0 (no method/stage limit) and the API is in no usage plan, so requests are bounded only by the us-east-1 account throttle of 10000 rps / 5000 burst shared by all nine APIs.
- **Why it matters:** A traffic surge against this one API (route `GET /items` runs DynamoDB `Scan`) can consume the regional account quota and throttle every other API Gateway API in the account.
- **Remediation:** Set explicit `throttlingRateLimit`/`throttlingBurstLimit` values on the stage (comparable to the 25 rps / 50 burst used on the other stages); end state is every production stage having its own throttle below the account limit.

### 7. Reporting API stage has no WAF web ACL association
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage `prod` has `web_acl_arn` null, while the other seven REST stages are associated with arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/1415ab8d-99c3-4cc5-be69-2a2e23b1dad4.
- **Why it matters:** This stage lacks the request-filtering layer applied to every other REST stage in the account, leaving the `GET /items` DynamoDB scan route without that inspection.
- **Remediation:** Associate the existing brightpath-apigateway web ACL with the `14gn38be16` prod stage so all REST stages share the same WAF coverage.

### 8. Inventory API stage writes no access logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage `prod` has `access_log_destination` null and `tracing_enabled` false, whereas the other REST stages log to /aws/apigateway/<api-name> log groups.
- **Why it matters:** No per-request record exists for this API, so invocations of the AWS_IAM-protected `GET /items` DynamoDB scan route cannot be investigated after the fact.
- **Remediation:** Set an `access_log_destination` CloudWatch log group with a request-identity log format on the prod stage; end state is access logging enabled on every stage.
