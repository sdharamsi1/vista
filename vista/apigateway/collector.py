"""Collect factual API Gateway configuration for a Bedrock security review.

Covers REST APIs (apigateway) and HTTP/WebSocket APIs (apigatewayv2), reshaped into one common
format: each API has its endpoint settings, resource policy, authorizers, request validators, routes
(with the authorization each one enforces), integrations, and stages. Region-wide context that APIs
depend on (account logging role and throttle, usage plans, VPC links, and custom domains) is
collected once per region, and only for regions that contain at least one API.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from botocore.config import Config

from vista.facts import isoformat, paginate, safe_call

# The API Gateway control plane is heavily rate-limited, so retry throttles with backoff.
RETRY_CONFIG = Config(retries={"mode": "standard", "max_attempts": 8})

# Error codes that mean "this configuration simply isn't set" rather than a real failure.
BENIGN_CODES = {"NotFoundException"}


# Run a getter, returning None for "not configured" and recording other errors in `errors`.
def _try(errors: dict[str, str], field: str, getter: Callable[[], Any]) -> Any:
    return safe_call(errors, field, getter, BENIGN_CODES)


# REST API policies come back as JSON with escaped quotes; decode to a dict when possible.
def _decode_policy(document: str | None) -> Any:
    if not document:
        return None
    for candidate in (document, document.replace('\\"', '"')):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return document


# Reduce a REST authorizer to its type, identity source, and backing Lambda/Cognito provider.
def _rest_authorizer(authorizer: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": authorizer.get("name"),
        "type": authorizer.get("type"),
        "provider_arns": authorizer.get("providerARNs"),
        "authorizer_uri": authorizer.get("authorizerUri"),
        "credentials_arn": authorizer.get("authorizerCredentials"),
        "identity_source": authorizer.get("identitySource"),
        "result_ttl_seconds": authorizer.get("authorizerResultTtlInSeconds"),
    }


# Flatten a REST resource's methods into routes, each carrying its integration inline.
def _rest_routes(resource: dict[str, Any]) -> list[dict[str, Any]]:
    routes = []
    for http_method, method in (resource.get("resourceMethods") or {}).items():
        integration = method.get("methodIntegration") or {}
        routes.append(
            {
                "route_key": f"{http_method} {resource.get('path')}",
                "authorization_type": method.get("authorizationType"),
                "authorizer_id": method.get("authorizerId"),
                "authorization_scopes": method.get("authorizationScopes"),
                "api_key_required": method.get("apiKeyRequired"),
                "request_validator_id": method.get("requestValidatorId"),
                "integration": {
                    "type": integration.get("type"),
                    "uri": integration.get("uri"),
                    "connection_type": integration.get("connectionType"),
                    "connection_id": integration.get("connectionId"),
                    "credentials_arn": integration.get("credentials"),
                    "tls_insecure_skip_verification": (integration.get("tlsConfig") or {}).get(
                        "insecureSkipVerification"
                    ),
                }
                if integration
                else None,
            }
        )
    return routes


# Reduce a REST stage to its WAF, client certificate, logging, tracing, and method settings.
def _rest_stage(stage: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage_name": stage.get("stageName"),
        "deployment_id": stage.get("deploymentId"),
        "web_acl_arn": stage.get("webAclArn"),
        "client_certificate_id": stage.get("clientCertificateId"),
        "access_log_destination": (stage.get("accessLogSettings") or {}).get("destinationArn"),
        "tracing_enabled": stage.get("tracingEnabled"),
        "cache_cluster_enabled": stage.get("cacheClusterEnabled"),
        "method_settings": stage.get("methodSettings") or {},
        "variable_names": sorted(stage.get("variables") or {}),
    }


# Collect one REST API with its authorizers, request validators, routes, and stages.
def _rest_api(client: Any, api: dict[str, Any], region: str) -> dict[str, Any]:
    api_id = api["id"]
    errors: dict[str, str] = {}
    resources = _try(
        errors,
        "resources",
        lambda: paginate(client, "get_resources", "items", restApiId=api_id, embed=["methods"]),
    )
    authorizers = _try(
        errors, "authorizers", lambda: paginate(client, "get_authorizers", "items", restApiId=api_id)
    )
    validators = _try(
        errors,
        "request_validators",
        lambda: paginate(client, "get_request_validators", "items", restApiId=api_id),
    )
    stages = _try(errors, "stages", lambda: paginate(client, "get_stages", "item", restApiId=api_id))
    endpoint = api.get("endpointConfiguration") or {}
    return {
        "api_id": api_id,
        "name": api.get("name"),
        "type": "REST",
        "region": region,
        "created_date": isoformat(api.get("createdDate")),
        "tags": api.get("tags") or {},
        "endpoint_types": endpoint.get("types", []),
        "ip_address_type": endpoint.get("ipAddressType"),
        "vpc_endpoint_ids": endpoint.get("vpcEndpointIds", []),
        "disable_execute_api_endpoint": api.get("disableExecuteApiEndpoint"),
        "api_key_source": api.get("apiKeySource"),
        "policy": _decode_policy(api.get("policy")),
        "authorizers": {item["id"]: _rest_authorizer(item) for item in authorizers or []},
        "request_validators": {
            item["id"]: {
                "name": item.get("name"),
                "validate_request_body": item.get("validateRequestBody"),
                "validate_request_parameters": item.get("validateRequestParameters"),
            }
            for item in validators or []
        },
        "routes": [route for resource in resources or [] for route in _rest_routes(resource)],
        "stages": [_rest_stage(stage) for stage in stages or []],
        "collection_errors": errors or None,
    }


# Reduce an HTTP/WebSocket authorizer to its type, identity source, and JWT or Lambda backing.
def _v2_authorizer(authorizer: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": authorizer.get("Name"),
        "type": authorizer.get("AuthorizerType"),
        "jwt_configuration": authorizer.get("JwtConfiguration"),
        "authorizer_uri": authorizer.get("AuthorizerUri"),
        "credentials_arn": authorizer.get("AuthorizerCredentialsArn"),
        "identity_source": authorizer.get("IdentitySource"),
        "result_ttl_seconds": authorizer.get("AuthorizerResultTtlInSeconds"),
    }


# Reduce an HTTP/WebSocket integration to its type, backend target, and TLS verification.
def _v2_integration(integration: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": integration.get("IntegrationType"),
        "uri": integration.get("IntegrationUri"),
        "connection_type": integration.get("ConnectionType"),
        "connection_id": integration.get("ConnectionId"),
        "credentials_arn": integration.get("CredentialsArn"),
        "tls_server_name_to_verify": (integration.get("TlsConfig") or {}).get(
            "ServerNameToVerify"
        ),
    }


# Reduce an HTTP/WebSocket route to its authorization and a reference to its integration.
def _v2_route(route: dict[str, Any]) -> dict[str, Any]:
    target = route.get("Target") or ""
    return {
        "route_key": route.get("RouteKey"),
        "authorization_type": route.get("AuthorizationType"),
        "authorizer_id": route.get("AuthorizerId"),
        "authorization_scopes": route.get("AuthorizationScopes"),
        "api_key_required": route.get("ApiKeyRequired"),
        "integration_id": target.removeprefix("integrations/") or None,
    }


# Reduce an HTTP/WebSocket stage to its logging, throttling, and client certificate settings.
def _v2_stage(stage: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage_name": stage.get("StageName"),
        "auto_deploy": stage.get("AutoDeploy"),
        "client_certificate_id": stage.get("ClientCertificateId"),
        "access_log_destination": (stage.get("AccessLogSettings") or {}).get("DestinationArn"),
        "default_route_settings": stage.get("DefaultRouteSettings"),
        "route_settings": stage.get("RouteSettings") or {},
        "variable_names": sorted(stage.get("StageVariables") or {}),
    }


# Collect one HTTP/WebSocket API with its authorizers, integrations, routes, and stages.
def _v2_api(client: Any, api: dict[str, Any], region: str) -> dict[str, Any]:
    api_id = api["ApiId"]
    errors: dict[str, str] = {}
    routes = _try(errors, "routes", lambda: paginate(client, "get_routes", "Items", ApiId=api_id))
    integrations = _try(
        errors, "integrations", lambda: paginate(client, "get_integrations", "Items", ApiId=api_id)
    )
    authorizers = _try(
        errors, "authorizers", lambda: paginate(client, "get_authorizers", "Items", ApiId=api_id)
    )
    stages = _try(errors, "stages", lambda: paginate(client, "get_stages", "Items", ApiId=api_id))
    return {
        "api_id": api_id,
        "name": api.get("Name"),
        "type": api.get("ProtocolType"),
        "region": region,
        "created_date": isoformat(api.get("CreatedDate")),
        "tags": api.get("Tags") or {},
        "api_endpoint": api.get("ApiEndpoint"),
        "ip_address_type": api.get("IpAddressType"),
        "disable_execute_api_endpoint": api.get("DisableExecuteApiEndpoint"),
        "cors": api.get("CorsConfiguration"),
        "authorizers": {item["AuthorizerId"]: _v2_authorizer(item) for item in authorizers or []},
        "integrations": {
            item["IntegrationId"]: _v2_integration(item) for item in integrations or []
        },
        "routes": [_v2_route(route) for route in routes or []],
        "stages": [_v2_stage(stage) for stage in stages or []],
        "collection_errors": errors or None,
    }


# Region-wide account settings: the CloudWatch role execution logging needs, and the throttle.
def _account_settings(v1: Any, region: str, errors: dict[str, str]) -> dict[str, Any] | None:
    account = _try(errors, "account", v1.get_account)
    if account is None:
        return None
    return {
        "region": region,
        "cloudwatch_role_arn": account.get("cloudwatchRoleArn"),
        "throttle": account.get("throttleSettings"),
    }


# Usage plans with their throttle, quota, attached API stages, and number of API keys.
def _usage_plans(v1: Any, region: str, errors: dict[str, str]) -> list[dict[str, Any]]:
    plans = []
    listed = _try(errors, "usage_plans", lambda: paginate(v1, "get_usage_plans", "items"))
    for plan in listed or []:
        plan_id = plan["id"]
        keys = _try(
            errors,
            f"usage_plan_keys:{plan_id}",
            lambda: paginate(v1, "get_usage_plan_keys", "items", usagePlanId=plan_id),
        )
        plans.append(
            {
                "id": plan_id,
                "name": plan.get("name"),
                "region": region,
                "throttle": plan.get("throttle"),
                "quota": plan.get("quota"),
                "api_stages": [
                    {
                        "api_id": stage.get("apiId"),
                        "stage": stage.get("stage"),
                        "throttle": stage.get("throttle"),
                    }
                    for stage in plan.get("apiStages", [])
                ],
                "api_key_count": len(keys) if keys is not None else None,
            }
        )
    return plans


# VPC links that private integrations reference by connection_id (REST: NLB targets; v2: subnets).
def _vpc_links(v1: Any, v2: Any, region: str, errors: dict[str, str]) -> list[dict[str, Any]]:
    rest_links = _try(errors, "vpc_links", lambda: paginate(v1, "get_vpc_links", "items"))
    v2_links = _try(errors, "vpc_links_v2", lambda: paginate(v2, "get_vpc_links", "Items"))
    links = [
        {
            "id": link.get("id"),
            "name": link.get("name"),
            "region": region,
            "target_arns": link.get("targetArns", []),
            "status": link.get("status"),
        }
        for link in rest_links or []
    ]
    links.extend(
        {
            "id": link.get("VpcLinkId"),
            "name": link.get("Name"),
            "region": region,
            "subnet_ids": link.get("SubnetIds", []),
            "security_group_ids": link.get("SecurityGroupIds", []),
            "status": link.get("VpcLinkStatus"),
        }
        for link in v2_links or []
    )
    return links


# API stages mapped to a custom domain; regional domains use v2 mappings, which cover every API type.
def _domain_mappings(
    v1: Any, v2: Any, domain: dict[str, Any], errors: dict[str, str]
) -> list[dict[str, Any]]:
    name = domain.get("domainName")
    types = (domain.get("endpointConfiguration") or {}).get("types", [])
    if types == ["REGIONAL"]:
        items = _try(
            errors, "mappings", lambda: paginate(v2, "get_api_mappings", "Items", DomainName=name)
        )
        return [
            {
                "base_path": item.get("ApiMappingKey") or "(none)",
                "api_id": item.get("ApiId"),
                "stage": item.get("Stage"),
            }
            for item in items or []
        ]
    lookup = {"domainName": name}
    if domain.get("domainNameId"):
        lookup["domainNameId"] = domain["domainNameId"]
    items = _try(
        errors, "mappings", lambda: paginate(v1, "get_base_path_mappings", "items", **lookup)
    )
    return [
        {
            "base_path": item.get("basePath"),
            "api_id": item.get("restApiId"),
            "stage": item.get("stage"),
        }
        for item in items or []
    ]


# Custom domain names with their endpoint type, TLS policy, mutual TLS, and mapped API stages.
def _domain_names(v1: Any, v2: Any, region: str, errors: dict[str, str]) -> list[dict[str, Any]]:
    domains = []
    listed = _try(errors, "domain_names", lambda: paginate(v1, "get_domain_names", "items"))
    for domain in listed or []:
        domain_errors: dict[str, str] = {}
        domains.append(
            {
                "domain_name": domain.get("domainName"),
                "region": region,
                "endpoint_types": (domain.get("endpointConfiguration") or {}).get("types", []),
                "security_policy": domain.get("securityPolicy"),
                "mutual_tls": domain.get("mutualTlsAuthentication"),
                "status": domain.get("domainNameStatus"),
                "mappings": _domain_mappings(v1, v2, domain, domain_errors),
                "collection_errors": domain_errors or None,
            }
        )
    return domains


# Collect every API in one region, plus region-wide context when the region has any API.
def scan_region(session: Any, region: str) -> dict[str, Any]:
    v1 = session.client("apigateway", region_name=region, config=RETRY_CONFIG)
    v2 = session.client("apigatewayv2", region_name=region, config=RETRY_CONFIG)
    errors: dict[str, str] = {}

    rest_apis = _try(errors, "rest_apis", lambda: paginate(v1, "get_rest_apis", "items")) or []
    v2_apis = _try(errors, "apis", lambda: paginate(v2, "get_apis", "Items")) or []
    apis = [_rest_api(v1, api, region) for api in rest_apis]
    apis.extend(_v2_api(v2, api, region) for api in v2_apis)

    facts: dict[str, Any] = {
        "region": region,
        "account_settings": None,
        "usage_plans": [],
        "vpc_links": [],
        "domain_names": [],
        "apis": sorted(apis, key=lambda api: (api["name"] or "", api["api_id"])),
    }
    if apis:
        facts["account_settings"] = _account_settings(v1, region, errors)
        facts["usage_plans"] = _usage_plans(v1, region, errors)
        facts["vpc_links"] = _vpc_links(v1, v2, region, errors)
        facts["domain_names"] = _domain_names(v1, v2, region, errors)
    facts["collection_errors"] = errors or None
    return facts
