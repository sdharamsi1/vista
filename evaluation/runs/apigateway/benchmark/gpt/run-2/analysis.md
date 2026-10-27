# API Gateway Security Review

## Account Risk Summary
The account has several directly reachable routes that invoke DynamoDB or an AWS proxy integration without caller authentication, plus one IAM-protected API that can consume the Region’s shared throttle capacity. The review covered 8 REST APIs and 1 HTTP API, with no WebSocket APIs, all in us-east-1.

## Top Findings

### 1. Public unauthenticated routes read and modify DynamoDB
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** Both APIs have `disable_execute_api_endpoint: false`, no `policy_ref`, and data routes with `authorization_type: NONE` and `api_key_required: false`. On `2jhbfrn3v6`, `GET /items`, `PUT /items`, and `DELETE /items` invoke DynamoDB Scan, PutItem, and DeleteItem using `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration`; on `q4ozo3nsg6`, `GET /items` invokes DynamoDB Scan using `arn:aws:iam::111122223333:role/brightpath-orders-api-integration`.
- **Why it matters:** Any unauthenticated caller reaching the default execute-api endpoints can invoke the configured reads and, for the loyalty API, create or delete records with the integration role’s permissions.
- **Remediation:** Change every data route from `authorization_type: NONE` to `AWS_IAM` or `COGNITO_USER_POOLS` with a valid `authorizer_id`. Also restrict each integration role to only the required DynamoDB table, actions, and key conditions.

### 2. Payment webhook route accepts unauthenticated requests
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `POST /webhooks/payments` has `authorization_type: NONE` and `api_key_required: false`, while `disable_execute_api_endpoint` is false. It references AWS_PROXY integration `dxkligt`, which uses `arn:aws:iam::111122223333:role/brightpath-webhooks-integration`; the supplied integration URI is null, so the target and backend behavior are unavailable.
- **Why it matters:** An external caller can submit arbitrary requests to a payment-related webhook route, and accepted requests invoke the configured integration under its IAM role. The exact downstream effect cannot be established because the integration target and backend code were not supplied.
- **Remediation:** Require a JWT, Lambda, or IAM authorizer on `POST /webhooks/payments`; for signed webhook protocols, have a Lambda authorizer or backend verify the provider’s signature and reject missing, invalid, expired, or replayed messages. Limit the integration role to the exact target and actions required.

### 3. Reporting API lacks an API-level throttle
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** The prod stage’s `*/*` method settings specify `throttlingBurstLimit: -1` and `throttlingRateLimit: -1.0`, and no usage plan covers this API. Requests are therefore limited only by the us-east-1 account throttle of burst 5000 and rate 10000, which is shared across the account’s APIs; `GET /items` requires `AWS_IAM`.
- **Why it matters:** A caller that already has permission to invoke this API can drive traffic toward the shared regional account limit, potentially reducing availability for other APIs in us-east-1.
- **Remediation:** Set finite `throttlingBurstLimit` and `throttlingRateLimit` values for `GET /items` or the stage’s `*/*` method setting. The resulting per-method or per-stage limit should be materially below the shared account limit and sized for expected reporting traffic.

### 4. Source-IP-restricted admin routes have no caller authentication
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `GET /items` and `DELETE /items` both use `authorization_type: NONE` and `api_key_required: false`; they invoke DynamoDB Scan and DeleteItem using `arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration`. Policy `pol-8796d633f8fa` allows Principal `*` and denies requests only when `aws:SourceIp` is not within `203.0.113.0/24`, leaving requests from that source range unauthenticated.
- **Why it matters:** Any caller able to originate through the allowed source range can read or delete records without presenting an authenticated identity.
- **Remediation:** Change both routes to `AWS_IAM` or a configured authorizer and require authorization in addition to the source-IP policy. Keep the IP restriction as a secondary control and constrain the integration role’s DynamoDB permissions.

### 5. Partner API uses an API key as its only caller control
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `authorization_type: NONE` while setting `api_key_required: true`; they invoke DynamoDB Scan and PutItem using `arn:aws:iam::111122223333:role/brightpath-partner-api-integration`. Usage plan `vqo9fk` has one attached key and applies throttling and quota, but API keys identify clients for usage control rather than authenticating or authorizing callers.
- **Why it matters:** Possession or disclosure of the single API key is sufficient to invoke both read and write operations, with no independently authenticated caller identity.
- **Remediation:** Configure `AWS_IAM`, Cognito, or a Lambda authorizer on both routes, retaining the API key only for per-client throttling and quota. Ensure authorization decisions distinguish partners and restrict write access as required.

### 6. Full reporting responses are written to execution logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** The prod stage’s `*/*` method setting has `dataTraceEnabled: true` and `loggingLevel: INFO`. Its `GET /items` route invokes DynamoDB Scan, so full request and response bodies are written to CloudWatch execution logs; the sensitivity of returned records and access to those logs were not supplied.
- **Why it matters:** Anyone who later obtains permission to read the execution log may also obtain complete API response bodies, increasing the exposure created by compromised or overly broad log access.
- **Remediation:** Set `dataTraceEnabled: false` for the prod stage while retaining metadata-level execution and access logging. If temporary body tracing is required, use a non-production stage or tightly time-bound it and restrict access to the log group.

### 7. Inventory API does not produce per-request access logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** The prod stage has `access_log_destination: null`, so API Gateway does not write an access log entry for each request. Although `loggingLevel: ERROR` enables error-level execution logging through the configured regional CloudWatch role, that does not provide a complete request audit trail.
- **Why it matters:** Successful or otherwise non-error requests may not be available for investigation, client attribution, or traffic analysis.
- **Remediation:** Configure the prod stage’s access-log destination to a dedicated CloudWatch Logs log group and use a structured format containing request ID, source IP, authenticated principal, route, status, latency, and response length. Retain logs according to the account’s security and audit requirements.
