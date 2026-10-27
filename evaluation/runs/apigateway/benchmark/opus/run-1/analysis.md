# API Gateway Security Review

## Account Risk Summary
Nine APIs were reviewed in us-east-1 (eight REST APIs and one HTTP API), all reachable over their default `execute-api` endpoints (`disable_execute_api_endpoint: false`) with no custom domains configured. Several REST routes and the HTTP webhook route enforce `authorization_type: NONE` while their integrations call DynamoDB or Lambda using an IAM `credentials_arn` role, making unauthenticated data access the dominant risk; secondary issues include full request/response body logging, an unthrottled unWAF'd stage, and a stage with no access logging.

## Top Findings

### 1. Unauthenticated read, write, and delete of DynamoDB data on brightpath-loyalty-points-api
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1)
- **Evidence:** All three routes (`GET /items`, `PUT /items`, `DELETE /items`) have `authorization_type: NONE`, `authorizer_id: null`, and `api_key_required: false`; each integration is type `AWS` to `dynamodb:action/Scan`, `PutItem`, and `DeleteItem` using `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration`. The API has no `policy_ref` (no resource policy) and `disable_execute_api_endpoint` is false, so the default endpoint accepts any caller.
- **Why it matters:** Any internet caller can scan, overwrite, and delete loyalty records with the integration role's DynamoDB permissions, with no caller identity recorded beyond request metadata.
- **Remediation:** Set `authorization_type` to `AWS_IAM` or attach a Cognito/JWT authorizer to all three routes (and restrict the integration role to the minimum DynamoDB actions), ending with no route on this API accepting `NONE`.

### 2. Unauthenticated DynamoDB Scan exposed on brightpath-orders-api
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** `GET /items` has `authorization_type: NONE`, `authorizer_id: null`, `api_key_required: false`, and integrates as type `AWS` to `arn:aws:apigateway:us-east-1:dynamodb:action/Scan` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-orders-api-integration`. No `policy_ref` is present and the default execute-api endpoint is enabled.
- **Why it matters:** Any unauthenticated caller can enumerate the orders table contents through the API using the integration role's permissions.
- **Remediation:** Require `AWS_IAM` or an authorizer on `GET /items`; end state is no anonymous access path to the Scan integration.

### 3. Unauthenticated HTTP API route invoking a Lambda integration with an IAM role
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `POST /webhooks/payments` has `authorization_type: NONE` and `authorizer_id: null`; integration `dxkligt` is `AWS_PROXY` with `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-webhooks-integration`, `authorizers` is empty, and the `$default` stage is reachable at `https://f76tda3ox7.execute-api.us-east-1.amazonaws.com` (throttle 10 rps / burst 20). HTTP APIs cannot be protected by a WAF web ACL.
- **Why it matters:** Any internet caller can submit arbitrary payment-webhook payloads that are processed by the backend with the integration role's permissions, with no caller authentication or signature verification at the gateway.
- **Remediation:** Attach a JWT or Lambda authorizer to `POST /webhooks/payments` (or enforce `AWS_IAM`), ending with the route rejecting requests that lack a validated caller credential or verified provider signature.

### 4. Admin API routes with no authentication, protected only by a source-IP resource policy
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `GET /items` and `DELETE /items` both use `authorization_type: NONE` with `api_key_required: false`, integrating to `dynamodb:action/Scan` and `DeleteItem` via `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration`. Resource policy `pol-8796d633f8fa` allows `execute-api:Invoke` for Principal `*` and denies requests whose `aws:SourceIp` is not in `203.0.113.0/24`; `authorizers` is empty.
- **Why it matters:** Any host within 203.0.113.0/24 — including a compromised or shared machine in that range — can read and delete admin data with no user identity required or logged.
- **Remediation:** Add `AWS_IAM` or a Cognito/JWT authorizer to both routes while keeping the IP-based Deny, so network location alone no longer grants admin data access.

### 5. Partner API relies on an API key as its only access control
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `authorization_type: NONE` with `api_key_required: true` and `api_key_source: HEADER`, integrating to `dynamodb:action/Scan` and `PutItem` via `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-partner-api-integration`; usage plan `vqo9fk` attaches 1 key with 10 rps / burst 20 and a 100,000-request monthly quota. The API has no `policy_ref` and no authorizers.
- **Why it matters:** API keys identify clients for throttling and quotas, not authentication, so anyone who obtains the single header value can read and write the partner data set within the plan's quota.
- **Remediation:** Add `AWS_IAM` (SigV4) or a JWT/Lambda authorizer to both routes and keep the API key only for usage-plan metering.

### 6. Full request and response bodies written to CloudWatch execution logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** The `prod` stage `method_settings` `*/*` sets `dataTraceEnabled: true` with `loggingLevel: INFO`, and `account_settings` for us-east-1 supplies `cloudwatch_role_arn` `arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch`, so execution logging is active for every method on the API.
- **Why it matters:** Every request and response body passing through the support-ticket API, including any credentials or customer content in payloads, is persisted in CloudWatch Logs and exposed to anyone with log read permissions.
- **Remediation:** Set `dataTraceEnabled` to false on the `prod` stage (keep `loggingLevel` at `ERROR`/`INFO` without data tracing), ending with no payload bodies in execution logs.

### 7. Reporting API stage has throttling disabled and no WAF web ACL
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** The `prod` stage `method_settings` `*/*` sets `throttlingBurstLimit: -1` and `throttlingRateLimit: -1.0` and `web_acl_arn: null`, unlike the other REST stages which set 50/25.0 and associate `arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/1415ab8d-99c3-4cc5-be69-2a2e23b1dad4`; the single route `GET /items` uses `AWS_IAM` and calls `dynamodb:action/Scan`.
- **Why it matters:** Requests to this stage are bounded only by the shared regional account limit (10,000 rps / 5,000 burst), so traffic here can exhaust capacity for every other API in the account, and no web ACL inspects the requests.
- **Remediation:** Set explicit stage or method throttle limits (e.g. matching the 25 rps / 50 burst used on peer stages) and associate the existing regional web ACL with this stage.

### 8. Inventory API stage writes no access logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** The `prod` stage has `access_log_destination: null` while every other REST stage logs to `/aws/apigateway/<api-name>`; the route `GET /items` uses `AWS_IAM` and integrates to `dynamodb:action/Scan` via `credentials_arn` `arn:aws:iam::111122223333:role/brightpath-inventory-api-integration`.
- **Why it matters:** No per-request record exists for this stage, so invocations of the DynamoDB Scan integration cannot be attributed or investigated.
- **Remediation:** Configure an `access_log_destination` CloudWatch log group for the `prod` stage so every request is logged, matching the other APIs.
