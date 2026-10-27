# API Gateway Security Review

## Account Risk Summary
The review covered 9 APIs in `us-east-1`: 8 REST APIs and 1 HTTP API, with no WebSocket APIs. The most significant risks are publicly reachable unauthenticated routes invoking role-backed integrations, along with one API whose unbounded stage throttle can consume shared regional API Gateway capacity.

## Top Findings

### 1. Public unauthenticated routes expose DynamoDB read and write operations
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1), `q4ozo3nsg6` (brightpath-orders-api, us-east-1)
- **Evidence:** Both APIs are REGIONAL, have `disable_execute_api_endpoint: false`, have no `policy_ref`, and enforce `authorization_type: NONE` with `api_key_required: false`. Routes on `2jhbfrn3v6` invoke DynamoDB `Scan`, `PutItem`, and `DeleteItem` through `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration`; `q4ozo3nsg6` exposes DynamoDB `Scan` through `arn:aws:iam::111122223333:role/brightpath-orders-api-integration`.
- **Why it matters:** Any internet caller can cause these APIs to execute the configured DynamoDB operations with their integration roles, enabling unauthenticated data reads and, for `2jhbfrn3v6`, writes and deletions.
- **Remediation:** Change every data route to `AWS_IAM`, `COGNITO_USER_POOLS`, or another authorizer with explicit caller authorization. Restrict each integration role and request mapping to only the required DynamoDB table, keys, attributes, and operations.

### 2. Public payment webhook accepts unauthenticated requests
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `POST /webhooks/payments` has `authorization_type: NONE` and `api_key_required: false`; the HTTP API has `disable_execute_api_endpoint: false` and a deployed `$default` stage. The route references AWS proxy integration `dxkligt`, configured with `arn:aws:iam::111122223333:role/brightpath-webhooks-integration`, but its integration URI is null, so the exact backend and blast radius cannot be verified.
- **Why it matters:** Any internet caller can submit requests to the payment webhook route and trigger its role-backed integration without API Gateway authenticating the sender.
- **Remediation:** Require cryptographic webhook authentication, such as validation by a Lambda authorizer or backend of a provider-signed timestamped payload, and reject missing, invalid, or replayed signatures. Grant the integration role only the permissions required for the verified webhook workflow.

### 3. Unbounded reporting stage can consume shared regional capacity
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** The `prod` stage's `*/*` method setting has `throttlingBurstLimit: -1` and `throttlingRateLimit: -1.0`, and no usage plan applies to this API. Requests are therefore bounded only by the shared `us-east-1` account throttle of burst 5,000 and rate 10,000 requests per second; invocation requires `AWS_IAM`.
- **Why it matters:** A principal already permitted to invoke `GET /items` can drive this API toward the regional account limit, potentially reducing capacity available to all nine APIs in the same Region.
- **Remediation:** Set positive stage or method-level `throttlingBurstLimit` and `throttlingRateLimit` values for `GET /items`, sized below the regional account limit. Monitor throttles and reserve sufficient shared capacity for the other APIs.

### 4. All Cognito pool users can invoke both customer read and write routes
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `9abf9333md` (brightpath-customer-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` use Cognito authorizer `gdgqeq` for user pool `arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_tNeygMqYv`, but both have `authorization_scopes: null`. They invoke DynamoDB `Scan` and `PutItem` using `arn:aws:iam::111122223333:role/brightpath-customer-api-integration`.
- **Why it matters:** Any caller able to obtain a valid token from the configured user pool receives the same API Gateway access to both data reading and writing, without route-level scopes separating those privileges.
- **Remediation:** Define distinct Cognito resource-server scopes for read and write access and require the appropriate `authorization_scopes` on each route. Keep backend authorization checks for item-level ownership and restrict the integration role to the necessary tables and operations.

### 5. API key is the only caller control for partner data operations
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` both have `authorization_type: NONE`; they require an API key but no authenticated principal. Usage plan `vqo9fk` has one attached key and limits it to 10 requests per second, burst 20, and 100,000 requests per month, while the routes invoke DynamoDB `Scan` and `PutItem` using `arn:aws:iam::111122223333:role/brightpath-partner-api-integration`.
- **Why it matters:** Possession or disclosure of the single API key is sufficient to read and write through the partner API; API keys identify clients for quotas but do not provide principal authorization.
- **Remediation:** Retain the usage plan for metering, but add `AWS_IAM`, Cognito, or a Lambda authorizer to authenticate and authorize each partner independently. Issue separate credentials per partner and revoke or rotate the existing shared key as appropriate.

### 6. Internal admin operations rely only on a source-IP allowlist
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` have `authorization_type: NONE` and invoke DynamoDB `DeleteItem` and `Scan` using `arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration`. Policy `pol-8796d633f8fa` allows `Principal: "*"` and denies requests whose `aws:SourceIp` is not `203.0.113.0/24`, leaving callers observed within that range unauthenticated.
- **Why it matters:** Any caller satisfying the network condition can perform the configured administrative read and deletion operations without presenting an authenticated identity.
- **Remediation:** Retain the source-IP restriction as defense in depth, but require `AWS_IAM` or a suitable authorizer on both routes and grant invocation only to designated administrative principals. Apply least privilege to the integration role and constrain deletion requests to authorized records.

### 7. Full request and response bodies are written to execution logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** The `prod` stage's `*/*` method setting has `dataTraceEnabled: true` and `loggingLevel: INFO`. Consequently, full request and response bodies for `GET /items`, which invokes DynamoDB `Scan`, are written to CloudWatch execution logs; the actual body contents and log-reader permissions were not supplied.
- **Why it matters:** Full payload logging creates an additional copy of API data accessible to principals with permission to read the CloudWatch log group.
- **Remediation:** Set `dataTraceEnabled` to `false` in production and use structured access logs that omit bodies, credentials, and sensitive headers. Restrict and periodically review CloudWatch Logs read permissions and retention.

### 8. Inventory requests lack per-request access logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** The `prod` stage has `access_log_destination: null`. Although execution logging is set to `ERROR`, that does not produce an access-log entry for every request to the `AWS_IAM`-protected `GET /items` route.
- **Why it matters:** Successful and denied calls may lack a consistent request-level audit record, weakening investigation and caller-attribution capabilities.
- **Remediation:** Configure `access_log_destination` to a protected CloudWatch Logs log group and use a structured format containing request ID, authenticated principal, route, status, latency, and source IP while excluding credentials and payload bodies.
