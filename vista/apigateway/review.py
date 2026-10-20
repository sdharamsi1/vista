"""API Gateway review spec: the service guidance and response validation for the Bedrock review."""

from __future__ import annotations

from typing import Any

from vista import findings

SPEC = findings.ReviewSpec(
    service="API Gateway",
    noun="API",
    categories=("ACCESS_CONTROL", "SECURITY_CONFIGURATION"),
    affected_label="Affected resources",
    affected_format=(
        "each API formatted as `api_id` (Name, region), or each custom domain as `domain_name`"
    ),
    summary=(
        "One or two sentences on the account's overall API Gateway security posture, the number "
        "of APIs reviewed by type, and the regions covered."
    ),
)

GUIDANCE = """Review the supplied factual AWS API Gateway configuration for one AWS account, which
may span one or more regions. The JSON contains real API identities and exact AWS API values for
every REST, HTTP, and WebSocket API in the selected regions. Each record includes its own "region"
field. Make all security judgments yourself; no local security conclusions are included.

The payload uses one common shape for all API types:
- apis[].type is REST, HTTP, or WEBSOCKET.
- apis[].routes[] lists every route ("METHOD /path" for REST and HTTP, the route key for
  WebSocket) with the authorization_type it enforces, its authorizer_id, and api_key_required.
- authorizer_id -> the same API's authorizers[id]; request_validator_id -> the same API's
  request_validators[id].
- REST routes carry their integration inline; HTTP and WebSocket routes reference the same API's
  integrations[integration_id]. An integration connection_id -> vpc_links[] with that id.
- apis[].policy_ref -> shared.policies[ref] (REST resource policy). A REST API with no policy_ref
  has no resource policy. HTTP and WebSocket APIs do not support resource policies.
- account_settings[] holds each region's CloudWatch logging role and account throttle.
- usage_plans[] list the API stages they apply to, their throttle and quota, and how many API keys
  are attached.
- domain_names[] are custom domains; each mapping's api_id and stage name the API stage it serves.
- Stage variable values are never collected; only variable_names are supplied.
- Backend code behind an integration is not collected.
A missing reference means the collector did not return that object, exactly as if it were absent.

Your task: identify the account's most significant API Gateway security risks and report only the
ones that genuinely matter. Return at most 10 findings, and fewer when fewer real risks exist.
Never manufacture findings to reach a count. Order findings from most to least severe.

AWS behavior relevant to the supplied fields:
- authorization_type NONE means API Gateway performs no caller authentication on that route.
- API Gateway uses API keys with usage plans to identify clients for throttling and quotas.
- When disable_execute_api_endpoint is false, clients can invoke the API through its default
  execute-api endpoint as well as through any custom domain mapped to it. Mutual TLS and base path
  mappings configured on a custom domain apply only to requests made through that domain name.
- In a REST API resource policy, aws:SourceIp, aws:SourceVpce, aws:SourceVpc, and
  aws:PrincipalOrgID conditions limit a statement to requests from the listed IP ranges, VPC
  endpoints, VPCs, or AWS Organization, and an explicit Deny overrides any Allow. A PRIVATE REST API
  can be invoked only through interface VPC endpoints for execute-api; an Allow statement for
  Principal "*" without an aws:SourceVpce or aws:SourceVpc condition applies to requests through
  any such VPC endpoint, including endpoints in other AWS accounts.
- A JWT authorizer validates the token's issuer and requires its aud claim (or client_id when aud
  is absent) to match one of the audience entries in its jwt_configuration. A Lambda authorizer
  with result_ttl_seconds above 0 caches its result for that many seconds, keyed on the
  identity_source values, and reuses it for requests with the same values. An authorizer applies
  only to routes whose authorizer_id references it.
- API Gateway assumes an integration's credentials_arn role to call the integration target, so
  that call has the role's permissions for every request the route accepts.
- AWS WAF web ACLs can be associated with REST API stages (web_acl_arn); HTTP and WebSocket APIs do
  not support WAF association.
- Throttle limits can be set on a REST stage or method (method_settings), on an HTTP or WebSocket
  stage or route (default_route_settings, route_settings), and per API key in usage plans. Requests
  not covered by any of these are limited only by the account-level limit for the Region in
  account_settings, which all APIs in the account share in that Region. A usage plan's throttle and
  quota apply per API key; a usage plan with no throttle and no quota sets no per-key limits.
- With an access_log_destination, API Gateway writes an access log entry for each request; a stage
  without one writes no access logs. REST execution logging requires a cloudwatch_role_arn in
  account_settings and a loggingLevel in method_settings. dataTraceEnabled true writes full request
  and response bodies to the execution log in CloudWatch Logs.
- A custom domain's security_policy sets the minimum TLS version clients can negotiate (TLS_1_0
  accepts TLS 1.0 and later; TLS_1_2 accepts TLS 1.2 and later). An integration uri that begins
  with http:// is called without TLS. tls_insecure_skip_verification true makes API Gateway skip
  checking that the integration endpoint's certificate is issued by a supported certificate
  authority. A client certificate (client_certificate_id) on a REST stage lets the backend verify
  that requests come from API Gateway.
- A REST method's request validator makes API Gateway validate the request parameters, the body,
  or both (validate_request_parameters, validate_request_body) before calling the integration.
- cacheDataEncrypted in method_settings controls whether cached responses are encrypted. A client
  can ask API Gateway to invalidate a cache entry with a Cache-Control: max-age=0 header;
  requireAuthorizationForCacheControl and unauthorizedCacheControlHeaderStrategy control whether
  that needs the execute-api:InvalidateCache permission and how requests without it are handled.

{SEVERITY_MODEL}

Assign each finding one Category by what it is about: ACCESS_CONTROL when it is about who can
invoke the APIs or their routes and the permissions those invocations run with,
SECURITY_CONFIGURATION when it is about any other API, stage, integration, or custom domain
configuration.
"""


# Every identifier a finding may cite: API IDs and custom domain names.
def identifiers(facts: dict[str, Any]) -> set[str]:
    ids = {api["api_id"] for api in facts.get("apis", [])}
    ids.update(domain["domain_name"] for domain in facts.get("domain_names", []))
    return ids


# Build the per-request system prompt with the API count.
def build_system_prompt(facts: dict[str, Any]) -> str:
    counts = f"{len(facts.get('apis', []))} APIs"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts)


# Validate the review structure and that every cited API ID or domain exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
