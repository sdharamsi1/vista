"""Collect factual ELBv2 relationships for EC2 instances."""

from __future__ import annotations

from typing import Any

from ec2.inventory import isoformat
from ec2.network import find_effective_route_table, load_security_groups

SOURCE_APIS = [
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeRules",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeRouteTables",
]


# Collect all items from a paginated boto operation into a single list.
def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[Any]:
    items = []
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


# Strip the ClientSecret from an OIDC auth config so the secret is never serialized.
def omit_client_secret(config: dict[str, Any] | None) -> dict[str, Any] | None:
    if not config:
        return None
    return {key: value for key, value in config.items() if key != "ClientSecret"}


# Normalize listener/rule actions into forward targets, auth actions, redirects, and fixed responses.
def normalize_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for action in actions:
        targets = [
            {"arn": item["TargetGroupArn"], "weight": item.get("Weight")}
            for item in (action.get("ForwardConfig") or {}).get("TargetGroups", [])
            if item.get("TargetGroupArn")
        ]
        if not targets and action.get("TargetGroupArn"):
            targets.append({"arn": action["TargetGroupArn"], "weight": None})
        normalized.append(
            {
                "type": action.get("Type"),
                "order": action.get("Order"),
                "forward_targets": targets,
                "authenticate_oidc": omit_client_secret(
                    action.get("AuthenticateOidcConfig")
                ),
                "authenticate_cognito": action.get("AuthenticateCognitoConfig"),
                "redirect": action.get("RedirectConfig"),
                "fixed_response": action.get("FixedResponseConfig"),
            }
        )
    return normalized


# Normalize a listener-rule condition into its field and matching configurations.
def normalize_condition(condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "field": condition.get("Field"),
        "values": condition.get("Values", []),
        "host_header": condition.get("HostHeaderConfig"),
        "path_pattern": condition.get("PathPatternConfig"),
        "http_header": condition.get("HttpHeaderConfig"),
        "http_request_method": condition.get("HttpRequestMethodConfig"),
        "query_string": condition.get("QueryStringConfig"),
        "source_ip": condition.get("SourceIpConfig"),
    }


# Walk each LB's listeners and rules, mapping every target group to the paths that forward to it.
def target_group_references(
    load_balancers: dict[str, dict[str, Any]], elbv2_client: Any
) -> dict[str, list[dict[str, Any]]]:
    references: dict[str, list[dict[str, Any]]] = {}
    for load_balancer_arn, load_balancer in load_balancers.items():
        listeners = paginate(
            elbv2_client,
            "describe_listeners",
            "Listeners",
            LoadBalancerArn=load_balancer_arn,
        )
        for listener in listeners:
            default_actions = normalize_actions(listener.get("DefaultActions", []))
            listener_record = {
                "listener_arn": listener.get("ListenerArn"),
                "protocol": listener.get("Protocol"),
                "port": listener.get("Port"),
                "ssl_policy": listener.get("SslPolicy"),
                "certificate_arns": [
                    item["CertificateArn"]
                    for item in listener.get("Certificates", [])
                    if item.get("CertificateArn")
                ],
                "default_actions": default_actions,
                "rules": [],
            }
            load_balancer["listeners"].append(listener_record)
            action_sets = [
                {
                    "rule_arn": None,
                    "priority": "default",
                    "conditions": [],
                    "actions": default_actions,
                }
            ]

            if load_balancer["type"] == "application":
                rules = paginate(
                    elbv2_client,
                    "describe_rules",
                    "Rules",
                    ListenerArn=listener["ListenerArn"],
                )
                for rule in rules:
                    if rule.get("IsDefault"):
                        continue
                    rule_record = {
                        "rule_arn": rule.get("RuleArn"),
                        "priority": rule.get("Priority"),
                        "conditions": [
                            normalize_condition(item)
                            for item in rule.get("Conditions", [])
                        ],
                        "actions": normalize_actions(rule.get("Actions", [])),
                    }
                    listener_record["rules"].append(rule_record)
                    action_sets.append(rule_record)

            for action_set in action_sets:
                authentication_actions = [
                    action["type"]
                    for action in action_set["actions"]
                    if action["type"] in {"authenticate-cognito", "authenticate-oidc"}
                ]
                for action in action_set["actions"]:
                    for target in action["forward_targets"]:
                        references.setdefault(target["arn"], []).append(
                            {
                                "load_balancer_arn": load_balancer_arn,
                                "listener_arn": listener.get("ListenerArn"),
                                "rule_arn": action_set["rule_arn"],
                                "rule_priority": action_set["priority"],
                                "rule_conditions": action_set["conditions"],
                                "authentication_actions": authentication_actions,
                                "forward_weight": target["weight"],
                            }
                        )
    return references


# Build a lookup from each instance's private IPs and IPv6 addresses to its instance ID.
def instance_ip_map(resources: list[dict[str, Any]]) -> dict[str, str]:
    result = {}
    for resource in resources:
        for interface in resource["network"]["interfaces"]:
            for address in interface["private_ipv4_addresses"]:
                if address.get("address"):
                    result[address["address"]] = resource["instance_id"]
            for address in interface["ipv6_addresses"]:
                result[address] = resource["instance_id"]
    return result


# Reduce a target group to its routing attributes and health-check settings.
def normalize_target_group(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "arn": group.get("TargetGroupArn"),
        "name": group.get("TargetGroupName"),
        "target_type": group.get("TargetType"),
        "protocol": group.get("Protocol"),
        "protocol_version": group.get("ProtocolVersion"),
        "port": group.get("Port"),
        "vpc_id": group.get("VpcId"),
        "health_check": {
            "enabled": group.get("HealthCheckEnabled"),
            "protocol": group.get("HealthCheckProtocol"),
            "port": group.get("HealthCheckPort"),
            "path": group.get("HealthCheckPath"),
            "interval_seconds": group.get("HealthCheckIntervalSeconds"),
            "timeout_seconds": group.get("HealthCheckTimeoutSeconds"),
            "healthy_threshold": group.get("HealthyThresholdCount"),
            "unhealthy_threshold": group.get("UnhealthyThresholdCount"),
            "matcher": group.get("Matcher"),
        },
    }


# Resolve every load-balancer path back to the instances it targets, keyed by instance ID.
def discover_relationships(
    elbv2_client: Any, ec2_client: Any, resources: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    raw_load_balancers = paginate(
        elbv2_client, "describe_load_balancers", "LoadBalancers"
    )
    load_balancers = {
        item["LoadBalancerArn"]: {
            "arn": item["LoadBalancerArn"],
            "name": item.get("LoadBalancerName"),
            "dns_name": item.get("DNSName"),
            "canonical_hosted_zone_id": item.get("CanonicalHostedZoneId"),
            "created_time": isoformat(item.get("CreatedTime")),
            "scheme": item.get("Scheme"),
            "type": item.get("Type"),
            "ip_address_type": item.get("IpAddressType"),
            "state": (item.get("State") or {}).get("Code"),
            "vpc_id": item.get("VpcId"),
            "security_group_ids": item.get("SecurityGroups", []),
            "subnet_ids": [
                zone.get("SubnetId")
                for zone in item.get("AvailabilityZones", [])
                if zone.get("SubnetId")
            ],
            "listeners": [],
        }
        for item in raw_load_balancers
    }

    group_ids = {
        group_id
        for load_balancer in load_balancers.values()
        for group_id in load_balancer["security_group_ids"]
    }
    security_groups = load_security_groups(ec2_client, group_ids)
    route_cache: dict[tuple[str, str | None], dict[str, Any] | None] = {}
    for load_balancer in load_balancers.values():
        load_balancer["security_groups"] = [
            security_groups[group_id]
            for group_id in load_balancer["security_group_ids"]
            if group_id in security_groups
        ]
        load_balancer["subnet_route_tables"] = []
        for subnet_id in load_balancer["subnet_ids"]:
            key = (subnet_id, load_balancer["vpc_id"])
            if key not in route_cache:
                route_cache[key] = find_effective_route_table(ec2_client, *key)
            load_balancer["subnet_route_tables"].append(
                {"subnet_id": subnet_id, "route_table": route_cache[key]}
            )

    references = target_group_references(load_balancers, elbv2_client)
    target_groups = {
        item["TargetGroupArn"]: item
        for item in paginate(elbv2_client, "describe_target_groups", "TargetGroups")
    }
    instance_ids = {resource["instance_id"] for resource in resources}
    ip_to_instance = instance_ip_map(resources)
    relationships: dict[str, list[dict[str, Any]]] = {}

    for target_group_arn, group_references in references.items():
        target_group = target_groups.get(target_group_arn)
        if not target_group:
            continue
        target_type = target_group.get("TargetType")
        health_descriptions = elbv2_client.describe_target_health(
            TargetGroupArn=target_group_arn
        ).get("TargetHealthDescriptions", [])
        for description in health_descriptions:
            target = description.get("Target") or {}
            target_id = target.get("Id")
            instance_id = (
                target_id
                if target_type == "instance" and target_id in instance_ids
                else ip_to_instance.get(target_id)
                if target_type == "ip"
                else None
            )
            if not instance_id:
                continue
            health = description.get("TargetHealth") or {}
            for reference in group_references:
                relationships.setdefault(instance_id, []).append(
                    {
                        "load_balancer": load_balancers[
                            reference["load_balancer_arn"]
                        ],
                        "listener_arn": reference["listener_arn"],
                        "rule_arn": reference["rule_arn"],
                        "rule_priority": reference["rule_priority"],
                        "rule_conditions": reference["rule_conditions"],
                        "authentication_actions": reference[
                            "authentication_actions"
                        ],
                        "forward_weight": reference["forward_weight"],
                        "target_group": normalize_target_group(target_group),
                        "target": {
                            "registered_id": target_id,
                            "resolved_instance_id": instance_id,
                            "port": target.get("Port"),
                            "availability_zone": target.get("AvailabilityZone"),
                            "health_state": health.get("State"),
                            "health_reason": health.get("Reason"),
                            "health_description": health.get("Description"),
                        },
                    }
                )
    return relationships


# Attach the discovered load-balancer relationships to each instance's network section.
def enrich_load_balancers(
    elbv2_client: Any, ec2_client: Any, resources: list[dict[str, Any]]
) -> None:
    relationships = discover_relationships(elbv2_client, ec2_client, resources)
    for resource in resources:
        resource["network"]["load_balancer_relationships"] = relationships.get(
            resource["instance_id"], []
        )
