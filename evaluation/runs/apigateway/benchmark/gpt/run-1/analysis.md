# API Gateway Security Review

## Account Risk Summary
The account has significant access-control exposure, including unauthenticated routes that directly invoke DynamoDB read and write operations. Nine APIs were reviewed in `us-east-1`: eight REST APIs, one HTTP API, and no WebSocket APIs.

## Top Findings

### 1. Public unauthenticated routes invoke DynamoDB read and write operations
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** Both APIs are REGIONAL, have `disable_execute_api_endpoint` set to false, and have no REST resource policy. On `2jhbfrn3v6`, `GET /items`, `PUT /items`, and `DELETE /items` use authorization type `NONE` and invoke DynamoDB `Scan`, `PutItem`, and `DeleteItem` through the `brightpath-loyalty-points-api-integration` role; `q4ozo3nsg6` exposes an equivalent unauthenticated `GET /items` DynamoDB `Scan` through the `brightpath-orders-api-integration` role.
- **Why it matters:** Any internet caller can cause API Gateway to execute the configured database operations with the integration roles. The exact tables and role permission boundaries were not supplied, but the configured operations permit unauthorized reading and, for the loyalty API, modification or deletion of workload data.
- **Remediation:** Change every data route from `NONE` to `AWS_IAM` or a correctly scoped Cognito/Lambda authorizer. Restrict each integration role to the required table, actions, keys, and attributes; add a restrictive REST resource policy if network or organization boundaries are required.

### 2. Any authenticated customer can invoke both inventory reads and writes
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `9abf9333md` (brightpath-customer-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` reference Cognito authorizer `gdgqeq`, backed by user pool `us-east-1_tNeygMqYv`, but both routes have `authorization_scopes` set to null. They invoke DynamoDB `Scan` and `PutItem` through the `brightpath-customer-api-integration` role.
- **Why it matters:** A valid token from the configured user pool is sufficient at API Gateway for both read and write routes; no route-level scope distinguishes those privileges. The supplied data does not establish whether integration mappings further constrain users to their own records.
- **Remediation:** Define separate Cognito resource-server scopes for item reads and writes, require the appropriate scope on each route, and use access tokens. Constrain integration mappings and the integration role so callers can access only the intended tables, records, and operations.

### 3. Internal administrative data operations rely only on a source-IP allowlist
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use authorization type `NONE` and invoke DynamoDB `DeleteItem` and `Scan` through the `brightpath-internal-admin-api-integration` role. Policy `pol-8796d633f8fa` allows Principal `"*"` and denies only when `aws:SourceIp` is not within `203.0.113.0/24`, making source IP the sole caller restriction.
- **Why it matters:** Any caller able to originate through the allowed CIDR can read or delete data without presenting an authenticated identity. The exact DynamoDB resources permitted to the integration role were not supplied.
- **Remediation:** Require `AWS_IAM` or a suitable authorizer on both routes in addition to the IP policy. Keep an explicit default deny and permit only required principals and network sources; restrict the integration role to the minimum table and key operations.

### 4. API key is used as the sole control for partner data access
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `api_key_required` set to true but authorization type `NONE`; they invoke DynamoDB `Scan` and `PutItem` through the `brightpath-partner-api-integration` role. Usage plan `vqo9fk` has one API key and applies throttling of 10 requests/second with burst 20 and a monthly quota of 100,000, but API keys identify clients for metering rather than authenticate callers.
- **Why it matters:** Possession of the API key is sufficient to read or write through these routes, without a cryptographically authenticated caller identity. The usage-plan limits bound request volume but do not prevent misuse by anyone who obtains the key.
- **Remediation:** Require `AWS_IAM`, OAuth/JWT, or a Lambda authorizer on both routes and retain the API key only for per-client usage accounting. Use distinct partner identities and least-privilege integration-role permissions.

### 5. Reporting API has no API-level throttle and can consume the shared regional quota
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage `prod` sets `throttlingBurstLimit` to `-1` and `throttlingRateLimit` to `-1.0`, and no applicable usage plan is supplied. Its `GET /items` route therefore relies on the shared `us-east-1` account throttle of rate 10,000 and burst 5,000; invoking the route requires `AWS_IAM`.
- **Why it matters:** A caller already authorized for this route can drive requests against the account-level regional limit, potentially reducing API Gateway capacity available to the other APIs in `us-east-1`.
- **Remediation:** Set finite `throttlingRateLimit` and `throttlingBurstLimit` values for `prod` or specifically for `GET /items`, sized below the shared account limit. Restrict `execute-api:Invoke` permission to required principals and routes.

### 6. Public payment webhook route has no API Gateway authentication
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** INSUFFICIENT
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `POST /webhooks/payments` uses authorization type `NONE`, and the public execute-api endpoint is enabled. Integration `dxkligt` is `AWS_PROXY` and specifies the `brightpath-webhooks-integration` credentials role, but its integration URI is null; backend signature validation was not collected.
- **Why it matters:** API Gateway accepts webhook requests from unauthenticated internet callers, so it does not establish the sender's identity or request integrity. Whether downstream validation prevents forged events cannot be determined because the integration target and backend behavior are missing.
- **Remediation:** Configure a Lambda authorizer or other Gateway-supported authentication where feasible, or require the backend to verify a provider-signed payload using a protected secret and reject replays before processing. Supply a valid, explicit integration URI and keep the existing route throttle bounded.

### 7. Full request and response bodies are written to execution logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage `prod` has `dataTraceEnabled` set to true and `loggingLevel` set to `INFO`; the regional CloudWatch role is `brightpath-apigateway-cloudwatch`. The route invokes DynamoDB `Scan`, causing full request and response bodies to be eligible for execution logging.
- **Why it matters:** Anyone with access to the execution log group can obtain complete logged payloads, expanding the exposure created by CloudWatch Logs permissions and retention. The supplied configuration does not establish what fields the payloads contain.
- **Remediation:** Set `dataTraceEnabled` to false in production while retaining error logging, metrics, and structured access logs. If body tracing is temporarily required, redact protected fields and tightly restrict log access and retention.

### 8. Inventory stage lacks per-request access logging
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage `prod` has `access_log_destination` set to null. Although execution logging is set to `ERROR`, the stage does not produce an access-log entry for every request.
- **Why it matters:** Successful calls and other requests that do not generate execution errors lack the stage-level audit trail needed for investigation and caller activity analysis.
- **Remediation:** Set `access_log_destination` to a dedicated CloudWatch Logs log group and configure a structured access-log format containing request ID, source, authenticated principal, route, status, latency, and response size.
