"""Collect factual IAM instance-profile, role, and policy configuration."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

from vista.ec2.inventory import isoformat

SOURCE_APIS = [
    "iam:GetInstanceProfile",
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
]


# Wrap a scalar in a list, pass a list through, and turn None into an empty list.
def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# Decode an IAM policy document that may arrive as a dict or a URL-encoded JSON string.
def decode_policy_document(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            decoded = json.loads(unquote(document))
            return decoded if isinstance(decoded, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


# Flatten a policy document into a version and a list of normalized statements.
def normalize_policy_document(document: Any) -> dict[str, Any]:
    decoded = decode_policy_document(document)
    statements = []
    for index, statement in enumerate(listify(decoded.get("Statement"))):
        if not isinstance(statement, dict):
            continue
        statements.append(
            {
                "statement_index": index,
                "sid": statement.get("Sid"),
                "effect": statement.get("Effect"),
                "actions": [str(item) for item in listify(statement.get("Action"))],
                "not_actions": [
                    str(item) for item in listify(statement.get("NotAction"))
                ],
                "resources": [
                    str(item) for item in listify(statement.get("Resource"))
                ],
                "not_resources": [
                    str(item) for item in listify(statement.get("NotResource"))
                ],
                "principal": statement.get("Principal"),
                "not_principal": statement.get("NotPrincipal"),
                "conditions": statement.get("Condition", {}),
            }
        )
    return {"version": decoded.get("Version"), "statements": statements}


# Collect all items from a paginated IAM operation into a single list.
def paginated_items(
    iam_client: Any, operation: str, result_key: str, **kwargs: Any
) -> list[Any]:
    items = []
    paginator = iam_client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


# Fetch a managed policy's default version and normalize it, caching by ARN.
def load_managed_policy(
    iam_client: Any, policy_arn: str, cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if policy_arn not in cache:
        metadata = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = metadata["DefaultVersionId"]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )["PolicyVersion"]
        cache[policy_arn] = {
            "type": "managed",
            "name": metadata.get("PolicyName"),
            "arn": policy_arn,
            "default_version_id": version_id,
            "document": normalize_policy_document(version.get("Document")),
        }
    return cache[policy_arn]


# Load a role's trust policy plus its attached managed and inline policies.
def load_role(
    iam_client: Any, role_name: str, managed_cache: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    role = iam_client.get_role(RoleName=role_name)["Role"]
    attached = paginated_items(
        iam_client,
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=role_name,
    )
    inline_names = paginated_items(
        iam_client, "list_role_policies", "PolicyNames", RoleName=role_name
    )
    policies = [
        load_managed_policy(iam_client, item["PolicyArn"], managed_cache)
        for item in attached
        if isinstance(item, dict) and item.get("PolicyArn")
    ]
    policies.extend(
        {
            "type": "inline",
            "name": policy_name,
            "arn": None,
            "document": normalize_policy_document(
                iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                ).get("PolicyDocument")
            ),
        }
        for policy_name in inline_names
        if isinstance(policy_name, str)
    )
    last_used = role.get("RoleLastUsed") or {}
    return {
        "role_name": role_name,
        "arn": role.get("Arn"),
        "role_id": role.get("RoleId"),
        "path": role.get("Path"),
        "permissions_boundary_arn": (role.get("PermissionsBoundary") or {}).get(
            "PermissionsBoundaryArn"
        ),
        "trust_policy": normalize_policy_document(
            role.get("AssumeRolePolicyDocument")
        ),
        "last_used": {
            "date": isoformat(last_used.get("LastUsedDate")),
            "region": last_used.get("Region"),
        },
        "policies": policies,
    }


# Fetch an instance profile and load each role it contains.
def load_instance_profile(
    iam_client: Any,
    profile_arn: str,
    managed_cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    profile_name = profile_arn.rsplit("/", 1)[-1]
    profile = iam_client.get_instance_profile(
        InstanceProfileName=profile_name
    )["InstanceProfile"]
    return {
        "name": profile.get("InstanceProfileName"),
        "arn": profile.get("Arn"),
        "id": profile.get("InstanceProfileId"),
        "path": profile.get("Path"),
        "roles": [
            load_role(iam_client, role["RoleName"], managed_cache)
            for role in profile.get("Roles", [])
            if role.get("RoleName")
        ],
    }


# Attach the resolved instance-profile details to each instance, caching profiles by ARN.
def enrich_iam(iam_client: Any, resources: list[dict[str, Any]]) -> None:
    profile_cache: dict[str, dict[str, Any]] = {}
    managed_cache: dict[str, dict[str, Any]] = {}
    for resource in resources:
        profile_arn = resource["iam"].get("instance_profile_arn")
        if profile_arn and profile_arn not in profile_cache:
            profile_cache[profile_arn] = load_instance_profile(
                iam_client, profile_arn, managed_cache
            )
        resource["iam"]["instance_profile"] = profile_cache.get(profile_arn)
