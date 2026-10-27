# API Gateway Security Review

## Account Risk Summary
The review covered 9 APIs in `us-east-1`: 8 REST APIs, 1 HTTP API, and no WebSocket APIs. The most significant risks are publicly reachable, unauthenticated DynamoDB operations and an authenticated API with no stage-level throttle, which can consume shared regional API Gateway capacity.

## Top Findings

### 1. Public routes invoke DynamoDB without caller authentication
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** Both APIs are REGIONAL, have `disable_execute_api_endpoint` set to `false`, and have no resource policy. On `2jhbfrn3v6`, `GET /items`, `PUT /items`, and `DELETE /items` use `authorization_type` `NONE` while invoking DynamoDB `Scan`, `PutItem`, and `DeleteItem` through `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration`; `q4ozo3nsg6` similarly exposes unauthenticated `GET /items` invoking DynamoDB `Scan` through `arn:aws:iam::111122223333:role/brightpath-orders-api-integration`.
- **Why it matters:** Any Internet caller can make API Gateway assume these integration roles and invoke the configured DynamoDB operations, including data insertion and deletion on the loyalty API.
- **Remediation:** Change all affected business routes from `NONE` to `AWS_IAM`, `COGNITO_USER_POOLS`, or an appropriate Lambda authorizer, and grant invocation only to authorized callers. If network restriction is also required, add a REST resource policy with explicit source conditions and a default deny.

### 2. Unthrottled reporting route can consume shared regional capacity
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** The `prod` stage has `throttlingBurstLimit` `-1` and `throttlingRateLimit` `-1.0`, and no usage plan covers this API. Consequently, authenticated requests to `GET /items` are limited only by the shared `us-east-1` account throttle of burst `5000` and rate `10000.0`.
- **Why it matters:** A principal already permitted to invoke this IAM-authorized route can generate enough requests to consume shared account-level API Gateway capacity, potentially degrading other APIs in `us-east-1`.
- **Remediation:** Configure finite positive `throttlingBurstLimit` and `throttlingRateLimit` values in the `prod` stage method settings for `GET /items` or `*/*`. Set them below the regional account limit and consistent with the reporting backend’s safe capacity.

### 3. Any valid user-pool identity can invoke customer data operations
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `9abf9333md` (brightpath-customer-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` use Cognito authorizer `gdgqeq` backed by user pool `arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_tNeygMqYv`, but both routes have `authorization_scopes` set to `null`. They invoke DynamoDB `Scan` and `PutItem` through `arn:aws:iam::111122223333:role/brightpath-customer-api-integration`.
- **Why it matters:** Possession of a valid token from the configured user pool is the only API Gateway authorization requirement; no route-level scope distinguishes read from write access.
- **Remediation:** Define separate OAuth scopes for reading and writing items and require the appropriate scope on each route. Alternatively, use a Lambda authorizer or backend authorization that enforces resource ownership and operation-specific permissions.

### 4. API key is the only gate protecting partner read and write operations
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` both have `authorization_type` `NONE`; their only API Gateway gate is `api_key_required` `true`. Usage plan `vqo9fk` has one attached key and applies throttling of burst `20`, rate `10.0`, and a monthly quota of `100000`, but API keys identify clients for metering rather than authenticate callers.
- **Why it matters:** Anyone who obtains the single API key can invoke DynamoDB `Scan` and `PutItem` through `arn:aws:iam::111122223333:role/brightpath-partner-api-integration` without a separate identity or authorization decision.
- **Remediation:** Add `AWS_IAM`, Cognito, or a Lambda authorizer to both routes and retain the API key only for per-client throttling and quotas. Issue distinct identities and keys per partner so access can be independently authorized and revoked.

### 5. Internal administrative operations rely solely on a source-IP policy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use `authorization_type` `NONE` and invoke DynamoDB `DeleteItem` and `Scan`. Resource policy `pol-8796d633f8fa` allows principal `*` and denies requests whose `aws:SourceIp` is not `203.0.113.0/24`, so callers from the allowed range receive no identity-based authentication.
- **Why it matters:** Any caller able to originate requests from the permitted source range can perform administrative read and delete operations through the integration role without presenting an authenticated identity.
- **Remediation:** Require `AWS_IAM`, Cognito, or a Lambda authorizer on both routes while retaining the IP restriction as an additional control. The end state should require both an authorized identity and an allowed network source.

### 6. Full request and response bodies are written to execution logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** The `prod` stage’s `*/*` method settings have `dataTraceEnabled` `true` and `loggingLevel` `INFO`. This causes full request and response bodies, including responses from the DynamoDB `Scan` integration on `GET /items`, to be written to CloudWatch execution logs.
- **Why it matters:** Body logging creates an additional copy of returned data in CloudWatch Logs and exposes it to principals with log-reading access.
- **Remediation:** Set `dataTraceEnabled` to `false` in the `prod` stage while retaining access logging and non-payload execution errors or metrics. Log only explicitly selected, non-sensitive metadata needed for troubleshooting.

### 7. Inventory stage has no per-request access logging
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** The `prod` stage has `access_log_destination` set to `null`. Although execution logging is configured at `ERROR`, it does not provide an access-log entry for every request.
- **Why it matters:** Successful and rejected requests may lack a consistent request-level audit record, reducing the ability to investigate misuse of the IAM-authorized inventory route.
- **Remediation:** Configure `access_log_destination` with a dedicated CloudWatch Logs log group and an access-log format containing request ID, source IP, authenticated principal, route, status, latency, and response size. Ensure every request produces an access-log entry without recording sensitive bodies or credentials.
