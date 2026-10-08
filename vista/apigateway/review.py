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
A missing reference means the collector did not return that object, exactly as if it were absent.

API Gateway endpoints are usually meant to be reachable from the Internet, so reachability alone
is not a finding and must not be reported as one. Assume each API serves real clients and judge
whether it is configured the way a well-secured production API should be: who can call each route,
how callers are authenticated and authorized, how abuse is limited, how traffic is protected in
transit, and whether activity is recorded.

Your task: identify the account's most significant API Gateway security misconfigurations and
report only the ones that genuinely matter. Return at most 10 findings, and fewer when fewer real
risks exist. Never manufacture findings to reach a count. Order findings from most to least severe.

Group, do not repeat. When multiple APIs, routes, or stages share the same root cause (the same
missing authorization, the same absent WAF, the same disabled logging), report them as a single
finding and list every affected API. Do not emit one finding per API, route, or stage.

Access control (who can call what):
- authorization_type NONE means API Gateway performs no caller authentication on that route. Flag
  it when the route can read or change data, invokes an AWS service action, or reaches an internal
  backend through a VPC link. OPTIONS routes with a MOCK integration are CORS preflight and are not
  a finding on their own.
- api_key_required is not authentication. API keys are identifiers for usage plans and are easily
  shared or leaked; a route protected only by an API key is effectively unauthenticated.
- disable_execute_api_endpoint false keeps the default execute-api URL reachable, so controls
  applied only at a custom domain (mutual TLS, a domain-level WAF or base path) can be bypassed.
- A REST resource policy allowing Principal "*" without a restricting condition (aws:SourceIp,
  aws:SourceVpce, aws:SourceVpc, aws:PrincipalOrgID) grants nothing beyond the default; one that
  denies or narrows callers is a positive control worth citing. For a PRIVATE API, a policy allowing
  Principal "*" without a VPC endpoint or VPC condition admits any VPC endpoint in any account.
- Authorizer weaknesses: a JWT authorizer without an audience, a Lambda authorizer whose
  identity_source omits the credential it validates combined with a long result_ttl_seconds, or an
  authorizer that is defined but not attached to the routes that need it.
- An integration with a credentials_arn executes with that role's permissions on behalf of every
  caller allowed to reach the route.
- CORS allowing any origin together with credentials.

Security configuration (protection, abuse limits, and visibility):
- WAF: a REST stage without web_acl_arn has no request filtering. HTTP and WebSocket APIs cannot
  attach WAF; do not report missing WAF for them.
- Throttling: no stage or route throttle in method_settings/default_route_settings, and no usage
  plan throttle or quota, leaves only the account-level limit in account_settings, so one client
  can consume the whole region's capacity. A usage plan with no throttle and no quota does not
  limit abuse.
- Logging: no access_log_destination means no record of callers. REST execution logging requires a
  cloudwatch_role_arn in account_settings and a loggingLevel in method_settings. dataTraceEnabled
  true logs full request and response bodies, which can capture credentials and personal data.
- TLS: a custom domain with security_policy TLS_1_0, an HTTP integration whose uri is plain http://,
  tls_insecure_skip_verification true, or an HTTP backend without a client certificate when the
  backend should only accept API Gateway.
- Input validation: REST methods that accept bodies or parameters with no request validator.
- Caching: a stage cache with cacheDataEncrypted false, or cache settings that let unauthorized
  callers invalidate entries.
- Stage variable names that suggest embedded secrets (password, secret, token, key).

{SEVERITY_MODEL}

For API Gateway specifically: an unauthenticated (NONE or API-key-only) route whose integration can
read or write data, invoke an AWS service action, or reach an internal backend is at least MEDIUM
Likelihood, and HIGH when the route is on a deployed stage of a non-private API. Missing WAF,
throttling, or logging are defense-in-depth gaps and are usually LOW or MEDIUM Likelihood on their
own; raise them only when they compound an access-control weakness on the same API. The backend
code is not supplied, so state that impact is inferred from the integration and reflect that in
Confidence. Supplied approved intent (for example, a deliberately anonymous public endpoint) may
lower Likelihood, but only with the reason stated.

Assign each finding a Category: ACCESS_CONTROL when the dominant risk is who can call the API
(authorization, API keys, resource policy, execute-api bypass, authorizer configuration, CORS, or
integration credentials), SECURITY_CONFIGURATION when it is WAF, throttling, logging, TLS, input
validation, caching, or stage configuration.

Be evidence-specific and concise:
- Cite exact supplied facts: API ID and name, region, endpoint type, route keys, authorization type,
  authorizer type and identity source, integration type and uri, stage names, web_acl_arn, log
  destinations, method or route settings, usage plan throttle and quota, policy statements and
  conditions, and domain security policies.
- Do not use vague labels such as "open" or "insecure" without the exact supporting fact. Do not
  claim data sensitivity, exploitation, or approved intent unless supplied.

For Remediation, give a concrete fix: the exact authorizer, setting, policy statement, or stage
configuration to change and the acceptable end state. Recommend confirming that an endpoint is
not intentionally anonymous before adding authorization to it.
"""


# Every identifier a finding may cite: API IDs and custom domain names.
def identifiers(facts: dict[str, Any]) -> set[str]:
    ids = {api["api_id"] for api in facts.get("apis", [])}
    ids.update(domain["domain_name"] for domain in facts.get("domain_names", []))
    return ids


# Build the per-request system prompt with the API count and, when supplied, account intent.
def build_system_prompt(facts: dict[str, Any], intent: str | None = None) -> str:
    counts = f"{len(facts.get('apis', []))} APIs"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts, intent)


# Validate the review structure and that every cited API ID or domain exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
