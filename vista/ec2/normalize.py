"""Deduplicate shared objects out of the per-instance facts into a top-level `shared` map.

Instances reference shared objects by ID (security groups, subnets, route tables, network ACLs,
instance profiles, managed policies, load balancers, target groups). This shrinks the payload sent
to Bedrock without dropping any information; the review prompt tells the model how to resolve the
references.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SHARED_KINDS = (
    "security_groups",
    "subnets",
    "route_tables",
    "network_acls",
    "instance_profiles",
    "managed_policies",
    "load_balancers",
    "target_groups",
)


# Store obj under key if absent; return the key so callers can reference it.
def _put(store: dict[str, Any], key: str | None, obj: dict[str, Any]) -> str | None:
    if key and key not in store:
        store[key] = obj
    return key


# Move a route table into shared, returning (route_table_id, association_type) for the reference.
def _extract_route_table(
    shared: dict[str, dict], table: dict[str, Any] | None
) -> tuple[str | None, str | None]:
    if not table:
        return None, None
    association_type = table.pop("association_type", None)
    _put(shared["route_tables"], table.get("route_table_id"), table)
    return table.get("route_table_id"), association_type


# Replace an instance profile's managed policy documents with references into shared.managed_policies.
def _extract_managed_policies(shared: dict[str, dict], profile: dict[str, Any]) -> None:
    for role in profile.get("roles", []):
        for policy in role.get("policies", []):
            if policy.get("type") == "managed" and policy.get("arn"):
                _put(shared["managed_policies"], policy["arn"], deepcopy(policy))
                policy.pop("document", None)


# Pull a load balancer's nested security groups and subnet route tables into shared.
def _extract_load_balancer(shared: dict[str, dict], load_balancer: dict[str, Any]) -> None:
    for group in load_balancer.pop("security_groups", []) or []:
        _put(shared["security_groups"], group.get("group_id"), group)
    for entry in load_balancer.get("subnet_route_tables", []):
        route_table_id, association_type = _extract_route_table(
            shared, entry.pop("route_table", None)
        )
        entry["route_table_id"] = route_table_id
        entry["route_table_association_type"] = association_type


# Rewrite one instance's network section to reference shared objects.
def _normalize_network(shared: dict[str, dict], network: dict[str, Any]) -> None:
    groups = network.pop("security_groups", []) or []
    for group in groups:
        _put(shared["security_groups"], group.get("group_id"), group)
    network["security_group_ids"] = sorted(
        group["group_id"] for group in groups if group.get("group_id")
    )

    for interface in network.get("interfaces", []):
        subnet = interface.pop("subnet", None)
        if subnet:
            _put(shared["subnets"], subnet.get("subnet_id"), subnet)
        route_table_id, association_type = _extract_route_table(
            shared, interface.pop("effective_route_table", None)
        )
        interface["route_table_id"] = route_table_id
        interface["route_table_association_type"] = association_type
        acl = interface.pop("network_acl", None)
        if acl:
            interface["network_acl_id"] = acl.get("network_acl_id")
            _put(shared["network_acls"], acl.get("network_acl_id"), acl)

    for relationship in network.get("load_balancer_relationships", []):
        load_balancer = relationship.pop("load_balancer", None)
        if load_balancer:
            _extract_load_balancer(shared, load_balancer)
            relationship["load_balancer_arn"] = load_balancer.get("arn")
            _put(shared["load_balancers"], load_balancer.get("arn"), load_balancer)
        target_group = relationship.pop("target_group", None)
        if target_group:
            relationship["target_group_arn"] = target_group.get("arn")
            _put(shared["target_groups"], target_group.get("arn"), target_group)


# Rewrite one instance's IAM section to reference a shared instance profile.
def _normalize_iam(shared: dict[str, dict], iam: dict[str, Any]) -> None:
    profile = iam.pop("instance_profile", None)
    if not profile:
        return
    profile_arn = iam.get("instance_profile_arn") or profile.get("arn")
    if profile_arn not in shared["instance_profiles"]:
        _extract_managed_policies(shared, profile)
        shared["instance_profiles"][profile_arn] = profile


# Return a normalized copy of the facts with shared objects deduplicated into `shared`.
def normalize(facts: dict[str, Any]) -> dict[str, Any]:
    facts = deepcopy(facts)
    shared: dict[str, dict] = {kind: {} for kind in SHARED_KINDS}

    for instance in facts.get("instances", []):
        if "network" in instance:
            _normalize_network(shared, instance["network"])
        if "iam" in instance:
            _normalize_iam(shared, instance["iam"])

    return {
        "scan": facts.get("scan", {}),
        "shared": {kind: table for kind, table in shared.items() if table},
        "instances": facts.get("instances", []),
    }
