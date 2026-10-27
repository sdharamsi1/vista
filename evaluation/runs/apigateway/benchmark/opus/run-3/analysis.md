# API Gateway Security Review

## Account Risk Summary
All 9 APIs (8 REST, 1 HTTP, 0 WebSocket) live in us-east-1 and every one is reachable over its default execute-api endpoint (`disable_execute_api_endpoint` false). Seven routes across four APIs enforce `authorization_type` NONE while their integrations carry an IAM `credentials_arn` to DynamoDB or Lambda, making unauthenticated data read, write, and delete the dominant risk; only `9abf9333md` (Cognito), `qijacgncdf`, `14gn38be16` and `7l3cra87nl` (AWS_IAM) authenticate callers.

## Top Findings

### 1. Unauthenticated public write and delete of DynamoDB data on the loyalty points API
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `2jhbfrn3v6` (brightpath-loyalty-points-api, us-east-1)
- **Evidence:** All three routes — `DELETE /items`, `PUT /items`, `GET /items` — have `authorization_type` NONE, `api_key_required` false, and no authorizer; each integration runs as `arn:aws:iam::111122223333:role/brightpath-loyalty-points-api-integration` against `dynamodb:action/DeleteItem`, `PutItem`, and `Scan`. The API has no `policy_ref` (no resource policy) and `disable_execute_api_endpoint` is false.
- **Why it matters:** Any anonymous caller on the internet can enumerate, overwrite, and delete every item the integration role can reach in DynamoDB, with only a 25 rps / 50 burst method throttle slowing bulk extraction or destruction.
- **Remediation:** Attach an authorizer (e.g. the Cognito user pool authorizer pattern used on `9abf9333md`) or set `authorization_type` to AWS_IAM on all three routes, and scope the integration role to the minimum DynamoDB actions and table required; end state is no route on this API accepting NONE.

### 2. Admin DeleteItem/Scan routes authenticated only by a source-IP resource policy
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `ht89xxg270` (brightpath-internal-admin-api, us-east-1)
- **Evidence:** `DELETE /items` and `GET /items` both use `authorization_type` NONE with `api_key_required` false and the integration role `arn:aws:iam::111122223333:role/brightpath-internal-admin-api-integration` calling `dynamodb:action/DeleteItem` and `Scan`. The only control is policy `pol-8796d633f8fa`, which Allows Principal `*` and Denies only when `aws:SourceIp` is outside `203.0.113.0/24`.
- **Why it matters:** Any caller whose traffic originates from the 203.0.113.0/24 range — including a compromised host, proxy, or NAT shared with other tenants in that range — gets unauthenticated administrative read and delete of the backing DynamoDB data.
- **Remediation:** Add caller authentication (AWS_IAM or a Cognito/JWT authorizer) to both methods and keep the IP Deny as defense in depth; end state is no NONE route on this API relying solely on `aws:SourceIp`.

### 3. Unauthenticated routes invoking privileged integrations on the orders and webhooks APIs
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** ACCESS_CONTROL
- **Affected resources:** `q4ozo3nsg6` (brightpath-orders-api, us-east-1), `f76tda3ox7` (brightpath-webhooks, us-east-1)
- **Evidence:** `q4ozo3nsg6` `GET /items` is `authorization_type` NONE with integration role `brightpath-orders-api-integration` calling `dynamodb:action/Scan`, and no `policy_ref`. `f76tda3ox7` `POST /webhooks/payments` is NONE, `api_key_required` false, integration `dxkligt` of type AWS_PROXY running as `brightpath-webhooks-integration`; HTTP APIs support no resource policy and no WAF.
- **Why it matters:** Anyone on the internet can scan the orders data set and submit arbitrary payment-webhook payloads that execute with the integration role's permissions; backend code behind `dxkligt` was not collected, so the write effect of forged webhooks is unbounded by any collected control.
- **Remediation:** Require authentication on both routes (AWS_IAM or a JWT/Lambda authorizer validating the webhook sender's signature) and narrow each integration role to the single table/function and actions needed.

### 4. Partner API write route gated only by an API key
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** ACCESS_CONTROL
- **Affected resources:** `7te8u58fhi` (brightpath-partner-api, us-east-1)
- **Evidence:** `GET /items` and `PUT /items` are `authorization_type` NONE with `api_key_required` true and `api_key_source` HEADER; usage plan `vqo9fk` attaches 1 key with 10 rps / 20 burst and a 100,000/MONTH quota to stage `prod`. The integration role `brightpath-partner-api-integration` performs `dynamodb:action/Scan` and `PutItem`.
- **Why it matters:** API keys identify clients for throttling, not authentication, so possession of the single header value gives any holder read and write access to the partner data set in DynamoDB.
- **Remediation:** Add a real authorizer (AWS_IAM signing or a JWT/Lambda authorizer per partner) on both methods and keep the API key only for usage-plan metering; end state is authentication independent of the key value.

### 5. Full request and response bodies written to execution logs on the support tickets API
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `7l3cra87nl` (brightpath-support-tickets-api, us-east-1)
- **Evidence:** Stage `prod` method settings `*/*` set `dataTraceEnabled` true with `loggingLevel` INFO, and `account_settings` for us-east-1 supplies `cloudwatch_role_arn arn:aws:iam::111122223333:role/brightpath-apigateway-cloudwatch`, so execution logging is active; all other APIs use `dataTraceEnabled` false with ERROR.
- **Why it matters:** Every request and response body traversing the ticket API — including anything callers submit through `GET /items` and whatever the DynamoDB `Scan` returns — is persisted in CloudWatch Logs and exposed to any principal with log read access.
- **Remediation:** Set `dataTraceEnabled` to false (and `loggingLevel` to ERROR) on the `prod` stage of `7l3cra87nl`; end state is no full-payload tracing on a production stage.

### 6. Reporting API stage has throttling disabled and no WAF, consuming the shared regional limit
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `14gn38be16` (brightpath-reporting-api, us-east-1)
- **Evidence:** Stage `prod` method settings `*/*` set `throttlingBurstLimit` -1 and `throttlingRateLimit` -1.0 (no method/stage limit) and `web_acl_arn` is null, unlike the other seven REST APIs which use 50/25.0 and the web ACL `arn:aws:wafv2:us-east-1:111122223333:regional/webacl/brightpath-apigateway/1415ab8d-99c3-4cc5-be69-2a2e23b1dad4`. The only remaining limit is the account setting of 10000 rps / 5000 burst for us-east-1.
- **Why it matters:** Request floods to this stage are bounded only by the regional limit that every API in the account shares, so saturating it can throttle the customer, orders, partner, and admin APIs as well.
- **Remediation:** Set a finite `throttlingRateLimit`/`throttlingBurstLimit` on the `14gn38be16` `prod` stage and associate the existing regional web ACL; end state is per-stage throttling in place for every production stage.

### 7. Inventory API stage writes no access logs
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `qijacgncdf` (brightpath-inventory-api, us-east-1)
- **Evidence:** Stage `prod` has `access_log_destination` null, while the other seven REST APIs and `f76tda3ox7` all log to `/aws/apigateway/<api-name>` log groups; `loggingLevel` is only ERROR and `tracing_enabled` is false.
- **Why it matters:** Invocations of the AWS_IAM-protected `GET /items` route (DynamoDB `Scan` via `brightpath-inventory-api-integration`) leave no per-request record, so abuse or credential misuse cannot be reconstructed.
- **Remediation:** Configure `access_log_destination` on the `qijacgncdf` `prod` stage to a CloudWatch log group matching the other APIs; end state is access logging enabled on every stage.
