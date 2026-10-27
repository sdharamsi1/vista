# API Gateway Security Review

## Account Risk Summary
The account has significant access-control exposure from publicly reachable, unauthenticated routes that invoke AWS integrations using IAM roles, plus one API that can consume the Region’s shared throttle without an API-level limit. The review covered 8 REST APIs and 1 HTTP API, with no WebSocket APIs, all in `us-east-1`.

## Top Findings

### 1. Public unauthenticated routes invoke data and webhook integrations
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1), `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `2jhbfrn3v6` exposes `DELETE /items`, `GET /items`, and `PUT /items` with `authorization_type` `NONE`, using an IAM role to call DynamoDB `DeleteItem`, `Scan`, and `PutItem`; `q4ozo3nsg6` similarly exposes unauthenticated `GET /items` to DynamoDB `Scan`. Neither REST API has a resource policy, and both have `disable_execute_api_endpoint` `false`; `f76tda3ox7` exposes unauthenticated `POST /webhooks/payments` through its enabled execute-api endpoint using an `AWS_PROXY` integration and the `brightpath-webhooks-integration` role, although its target URI is absent.
- **Why it matters:** Any Internet caller can directly trigger the configured data operations on the two REST APIs. The webhook route likewise accepts unauthenticated requests under an integration role, but its exact target and resulting impact cannot be established because the integration URI is missing.
- **Remediation:** Set these routes to an appropriate caller-authentication mechanism such as `AWS_IAM`, Cognito/JWT, or a Lambda authorizer, and grant invoke access only to intended identities. Where Internet access is unnecessary, add restrictive REST resource policies and disable the default execute-api endpoints.

### 2. Reporting API lacks an API-level throttle and can consume the shared Regional limit
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** The `prod` stage’s `*/*` method settings have `throttlingBurstLimit` `-1` and `throttlingRateLimit` `-1.0`, and no usage plan applies to this API. Requests are therefore bounded only by the shared `us-east-1` account throttle of burst `5000` and rate `10000.0`; exploitation requires an IAM principal permitted to invoke `GET /items`, and those IAM policies were not supplied.
- **Why it matters:** A permitted, compromised, or abusive caller could drive this API toward the shared Regional quota, potentially reducing availability for all nine APIs in `us-east-1`.
- **Remediation:** Configure finite `throttlingRateLimit` and `throttlingBurstLimit` values for `prod`, preferably with a tighter route-specific limit for `GET /items`. Set limits below the shared account throttle with sufficient capacity reserved for other APIs.

### 3. Every Cognito user can invoke both read and write data operations
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `9abf9333md` (brightpath-customer-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` both reference Cognito authorizer `gdgqeq`, which trusts user pool `us-east-1_tNeygMqYv`, but both routes have no `authorization_scopes`. These routes directly invoke DynamoDB `Scan` and `PutItem` using the `brightpath-customer-api-integration` IAM role.
- **Why it matters:** Any caller able to obtain a valid token from the configured user pool can invoke both read and write operations; API Gateway enforces no route-level privilege distinction between them.
- **Remediation:** Define separate Cognito OAuth scopes for read and write operations and populate each route’s `authorization_scopes` accordingly. Ensure only intended app clients and users can receive the write scope, and restrict the integration role to the exact table and actions required.

### 4. Internal admin data operations rely only on source-IP filtering
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use `authorization_type` `NONE` and invoke DynamoDB `DeleteItem` and `Scan` through the `brightpath-internal-admin-api-integration` role. Policy `pol-8796d633f8fa` allows Principal `*` and denies requests only when `aws:SourceIp` is outside `203.0.113.0/24`.
- **Why it matters:** Any request originating from the allowed CIDR can perform the configured admin read or delete operation without presenting an authenticated identity.
- **Remediation:** Require `AWS_IAM` or another authorizer on both routes while retaining the IP restriction as defense in depth. Limit `execute-api:Invoke` to specific principals, and constrain the integration role to the exact DynamoDB resources required.

### 5. Partner data access uses an API key without caller authentication
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` have `authorization_type` `NONE`; although `api_key_required` is `true`, API keys identify clients for usage-plan controls rather than authenticate callers. Usage plan `vqo9fk` has one attached key and permits calls at rate `10.0`, burst `20`, and quota `100000` per month.
- **Why it matters:** Anyone who obtains the API key can invoke DynamoDB `Scan` and `PutItem` through the API’s integration role without any independently authenticated identity.
- **Remediation:** Add `AWS_IAM`, Cognito/JWT, or a Lambda authorizer to both routes and use the API key only for per-client metering and throttling. Rotate the existing key after authentication is introduced and issue distinct keys to separately accountable clients.

### 6. Full support-ticket request and response bodies are written to execution logs
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** The `prod` stage enables `dataTraceEnabled` `true` with `loggingLevel` `INFO` for `*/*`. Consequently, full request and response bodies for `GET /items`, which invokes DynamoDB `Scan`, are written to CloudWatch execution logs; the sensitivity of those bodies and access to the log group were not supplied.
- **Why it matters:** API payloads are duplicated into CloudWatch Logs and become available to principals with log-reading permissions, increasing exposure and retention scope.
- **Remediation:** Set `dataTraceEnabled` to `false` for `prod` and retain structured access logging without request or response bodies. Restrict CloudWatch Logs access and review existing execution-log retention and contents.

### 7. Inventory API does not produce per-request access logs
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** The `prod` stage has `access_log_destination` set to `null`. Although REST execution logging is configured at `ERROR`, it does not provide an access-log entry for every request.
- **Why it matters:** Successful and non-error requests may lack a consistent audit record, reducing the ability to investigate misuse of the IAM-authorized DynamoDB `Scan` route.
- **Remediation:** Configure `access_log_destination` to a dedicated CloudWatch log group and set an access-log format containing request ID, caller identity, source IP, route, status, latency, and response size. Apply suitable retention and least-privilege log access.
