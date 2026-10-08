"""Collect factual RDS configuration for a Bedrock security review.

Covers DB instances, DB clusters (Aurora and Multi-AZ clusters), RDS Proxies, and manual snapshots
with their sharing attributes. Network context (security groups, subnet groups, subnets, route
tables, and network ACLs), user-modified parameter group settings, and KMS key ownership are
collected once into a `shared` map and referenced by ID, reusing the EC2 network collectors so both
services describe the network the same way.
"""

from __future__ import annotations

from typing import Any, Callable

from vista.ec2.network import (
    find_effective_route_table,
    find_network_acl,
    load_security_groups,
    load_subnets,
)
from vista.facts import isoformat, normalize_tags, paginate, safe_call

# Error codes that mean "this resource is gone or not configured" rather than a real failure.
BENIGN_CODES = {
    "DBSnapshotNotFound",
    "DBClusterSnapshotNotFoundFault",
    "DBParameterGroupNotFound",
    "DBClusterParameterGroupNotFound",
}


# Run a getter, returning None for "not configured" and recording other errors in `errors`.
def _try(errors: dict[str, str], field: str, getter: Callable[[], Any]) -> Any:
    return safe_call(errors, field, getter, BENIGN_CODES)


# Region-qualified key for RDS names that are only unique within a region.
def _ref(region: str, name: str | None) -> str | None:
    return f"{region}/{name}" if name else None


# Sorted VPC security group IDs from an instance or cluster record.
def _security_group_ids(item: dict[str, Any]) -> list[str]:
    return sorted(
        group["VpcSecurityGroupId"]
        for group in item.get("VpcSecurityGroups", [])
        if group.get("VpcSecurityGroupId")
    )


# Master password management: whether Secrets Manager holds it, and that secret's status.
def _master_secret(item: dict[str, Any]) -> dict[str, Any] | None:
    secret = item.get("MasterUserSecret")
    if not secret:
        return None
    return {"secret_arn": secret.get("SecretArn"), "status": secret.get("SecretStatus")}


# IAM roles the database itself can assume (for example S3 import/export or Lambda invoke).
def _associated_roles(item: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"role_arn": role.get("RoleArn"), "feature": role.get("FeatureName")}
        for role in item.get("AssociatedRoles", [])
    ]


# Reduce a DB instance to its exposure, network, encryption, authentication, and resilience facts.
def _instance(item: dict[str, Any], region: str) -> dict[str, Any]:
    endpoint = item.get("Endpoint") or {}
    subnet_group = item.get("DBSubnetGroup") or {}
    certificate = item.get("CertificateDetails") or {}
    return {
        "identifier": item["DBInstanceIdentifier"],
        "arn": item.get("DBInstanceArn"),
        "region": region,
        "tags": normalize_tags(item.get("TagList")),
        "engine": item.get("Engine"),
        "engine_version": item.get("EngineVersion"),
        "engine_lifecycle_support": item.get("EngineLifecycleSupport"),
        "instance_class": item.get("DBInstanceClass"),
        "status": item.get("DBInstanceStatus"),
        "cluster_identifier": item.get("DBClusterIdentifier"),
        "read_replica_source": item.get("ReadReplicaSourceDBInstanceIdentifier"),
        "publicly_accessible": item.get("PubliclyAccessible"),
        "endpoint": endpoint.get("Address"),
        "port": endpoint.get("Port"),
        "vpc_id": subnet_group.get("VpcId"),
        "subnet_group_ref": _ref(region, subnet_group.get("DBSubnetGroupName")),
        "security_group_ids": _security_group_ids(item),
        "storage_encrypted": item.get("StorageEncrypted"),
        "kms_key_id": item.get("KmsKeyId"),
        "iam_auth_enabled": item.get("IAMDatabaseAuthenticationEnabled"),
        "master_username": item.get("MasterUsername"),
        "master_user_secret": _master_secret(item),
        "associated_roles": _associated_roles(item),
        "ca_certificate": {
            "identifier": certificate.get("CAIdentifier") or item.get("CACertificateIdentifier"),
            "valid_till": isoformat(certificate.get("ValidTill")),
        },
        "parameter_group_refs": [
            _ref(region, group.get("DBParameterGroupName"))
            for group in item.get("DBParameterGroups", [])
        ],
        "deletion_protection": item.get("DeletionProtection"),
        "backup_retention_days": item.get("BackupRetentionPeriod"),
        "multi_az": item.get("MultiAZ"),
        "auto_minor_version_upgrade": item.get("AutoMinorVersionUpgrade"),
        "log_exports": item.get("EnabledCloudwatchLogsExports") or [],
        "monitoring_interval_seconds": item.get("MonitoringInterval"),
    }


# Reduce a DB cluster to its exposure, network, encryption, authentication, and resilience facts.
def _cluster(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "identifier": item["DBClusterIdentifier"],
        "arn": item.get("DBClusterArn"),
        "region": region,
        "tags": normalize_tags(item.get("TagList")),
        "engine": item.get("Engine"),
        "engine_version": item.get("EngineVersion"),
        "engine_mode": item.get("EngineMode"),
        "engine_lifecycle_support": item.get("EngineLifecycleSupport"),
        "status": item.get("Status"),
        "members": [
            {
                "identifier": member.get("DBInstanceIdentifier"),
                "writer": member.get("IsClusterWriter"),
            }
            for member in item.get("DBClusterMembers", [])
        ],
        "publicly_accessible": item.get("PubliclyAccessible"),
        "endpoint": item.get("Endpoint"),
        "reader_endpoint": item.get("ReaderEndpoint"),
        "port": item.get("Port"),
        "subnet_group_ref": _ref(region, item.get("DBSubnetGroup")),
        "security_group_ids": _security_group_ids(item),
        "storage_encrypted": item.get("StorageEncrypted"),
        "kms_key_id": item.get("KmsKeyId"),
        "iam_auth_enabled": item.get("IAMDatabaseAuthenticationEnabled"),
        "data_api_enabled": item.get("HttpEndpointEnabled"),
        "master_username": item.get("MasterUsername"),
        "master_user_secret": _master_secret(item),
        "associated_roles": _associated_roles(item),
        "cluster_parameter_group_ref": _ref(region, item.get("DBClusterParameterGroup")),
        "deletion_protection": item.get("DeletionProtection"),
        "backup_retention_days": item.get("BackupRetentionPeriod"),
        "log_exports": item.get("EnabledCloudwatchLogsExports") or [],
        "activity_stream_status": item.get("ActivityStreamStatus"),
    }


# Reduce an RDS Proxy to its TLS requirement, client authentication, network, and debug logging.
def _proxy(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "identifier": item["DBProxyName"],
        "arn": item.get("DBProxyArn"),
        "region": region,
        "engine_family": item.get("EngineFamily"),
        "status": item.get("Status"),
        "endpoint": item.get("Endpoint"),
        "vpc_id": item.get("VpcId"),
        "subnet_ids": sorted(item.get("VpcSubnetIds", [])),
        "security_group_ids": sorted(item.get("VpcSecurityGroupIds", [])),
        "require_tls": item.get("RequireTLS"),
        "debug_logging": item.get("DebugLogging"),
        "role_arn": item.get("RoleArn"),
        "default_auth_scheme": item.get("DefaultAuthScheme"),
        "auth": [
            {
                "auth_scheme": auth.get("AuthScheme"),
                "iam_auth": auth.get("IAMAuth"),
                "secret_arn": auth.get("SecretArn"),
                "client_password_auth_type": auth.get("ClientPasswordAuthType"),
            }
            for auth in item.get("Auth", [])
        ],
    }


# Reduce a manual snapshot to its source, encryption, and the accounts it is shared with.
def _snapshot(item: dict[str, Any], kind: str, region: str, shared_with: Any) -> dict[str, Any]:
    prefix = "DBClusterSnapshot" if kind == "cluster" else "DBSnapshot"
    return {
        "identifier": item[f"{prefix}Identifier"],
        "arn": item.get(f"{prefix}Arn"),
        "kind": kind,
        "region": region,
        "source": item.get("DBClusterIdentifier") or item.get("DBInstanceIdentifier"),
        "engine": item.get("Engine"),
        "created": isoformat(item.get("SnapshotCreateTime")),
        "encrypted": item.get("StorageEncrypted", item.get("Encrypted")),
        "kms_key_id": item.get("KmsKeyId"),
        "shared_with": shared_with,
    }


# "restore" attribute values for a snapshot: "all" means public, otherwise the shared account IDs.
def _restore_values(result: dict[str, Any] | None, result_key: str, list_key: str) -> Any:
    if result is None:
        return None
    for attribute in result.get(result_key, {}).get(list_key, []):
        if attribute.get("AttributeName") == "restore":
            return attribute.get("AttributeValues", [])
    return []


# Collect manual instance and cluster snapshots with their sharing attributes.
def _snapshots(rds: Any, region: str, errors: dict[str, str]) -> list[dict[str, Any]]:
    snapshots = []
    instance_snapshots = _try(
        errors,
        "db_snapshots",
        lambda: paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"),
    )
    for item in instance_snapshots or []:
        name = item["DBSnapshotIdentifier"]
        result = _try(
            errors,
            f"snapshot_attributes:{name}",
            lambda: rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=name),
        )
        shared = _restore_values(result, "DBSnapshotAttributesResult", "DBSnapshotAttributes")
        snapshots.append(_snapshot(item, "instance", region, shared))

    cluster_snapshots = _try(
        errors,
        "db_cluster_snapshots",
        lambda: paginate(
            rds, "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"
        ),
    )
    for item in cluster_snapshots or []:
        name = item["DBClusterSnapshotIdentifier"]
        result = _try(
            errors,
            f"snapshot_attributes:{name}",
            lambda: rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=name),
        )
        shared = _restore_values(
            result, "DBClusterSnapshotAttributesResult", "DBClusterSnapshotAttributes"
        )
        snapshots.append(_snapshot(item, "cluster", region, shared))
    return snapshots


# User-modified parameters of each referenced parameter group; default groups carry engine defaults.
def _parameter_groups(
    rds: Any, region: str, names: set[str], errors: dict[str, str], *, cluster: bool
) -> dict[str, dict[str, Any]]:
    operation = "describe_db_cluster_parameters" if cluster else "describe_db_parameters"
    argument = "DBClusterParameterGroupName" if cluster else "DBParameterGroupName"
    groups = {}
    for name in sorted(names):
        parameters = []
        if not name.startswith("default."):
            parameters = _try(
                errors,
                f"parameters:{name}",
                lambda: paginate(rds, operation, "Parameters", Source="user", **{argument: name}),
            ) or []
        groups[_ref(region, name)] = {
            "name": name,
            "is_default": name.startswith("default."),
            "user_parameters": {
                item["ParameterName"]: item.get("ParameterValue")
                for item in parameters
                if item.get("ParameterName")
            },
        }
    return groups


# Whether each referenced KMS key is AWS-managed (aws/rds) or customer-managed.
def _kms_keys(session: Any, region: str, key_ids: set[str], errors: dict[str, str]) -> dict:
    if not key_ids:
        return {}
    kms = session.client("kms", region_name=region)
    keys = {}
    for key_id in sorted(key_ids):
        described = _try(errors, f"kms:{key_id}", lambda: kms.describe_key(KeyId=key_id))
        if described:
            metadata = described.get("KeyMetadata", {})
            keys[key_id] = {
                "key_manager": metadata.get("KeyManager"),
                "key_state": metadata.get("KeyState"),
            }
    return keys


# Collect the referenced security groups, subnet groups, subnets, route tables, and NACLs.
def _network(
    session: Any,
    rds: Any,
    region: str,
    resources: list[dict[str, Any]],
    errors: dict[str, str],
) -> dict[str, dict[str, Any]]:
    shared: dict[str, dict[str, Any]] = {
        "security_groups": {},
        "subnet_groups": {},
        "subnets": {},
        "route_tables": {},
        "network_acls": {},
    }
    if not resources:
        return shared
    ec2 = session.client("ec2", region_name=region)
    group_ids = {group_id for item in resources for group_id in item["security_group_ids"]}
    group_refs = {item.get("subnet_group_ref") for item in resources} - {None}

    listed = _try(
        errors, "subnet_groups", lambda: paginate(rds, "describe_db_subnet_groups", "DBSubnetGroups")
    )
    for group in listed or []:
        ref = _ref(region, group.get("DBSubnetGroupName"))
        if ref in group_refs:
            shared["subnet_groups"][ref] = {
                "name": group.get("DBSubnetGroupName"),
                "vpc_id": group.get("VpcId"),
                "subnet_ids": sorted(
                    subnet["SubnetIdentifier"]
                    for subnet in group.get("Subnets", [])
                    if subnet.get("SubnetIdentifier")
                ),
            }
    subnet_ids = {
        subnet_id for group in shared["subnet_groups"].values() for subnet_id in group["subnet_ids"]
    }
    subnet_ids.update(subnet_id for item in resources for subnet_id in item.get("subnet_ids", []))

    shared["security_groups"] = (
        _try(errors, "security_groups", lambda: load_security_groups(ec2, group_ids)) or {}
    )
    shared["subnets"] = _try(errors, "subnets", lambda: load_subnets(ec2, subnet_ids)) or {}
    for subnet_id, subnet in shared["subnets"].items():
        table = _try(
            errors,
            f"route_table:{subnet_id}",
            lambda: find_effective_route_table(ec2, subnet_id, subnet.get("vpc_id")),
        )
        subnet["route_table_association_type"] = (table or {}).pop("association_type", None)
        subnet["route_table_id"] = (table or {}).get("route_table_id")
        if table:
            shared["route_tables"].setdefault(table["route_table_id"], table)
        acl = _try(errors, f"network_acl:{subnet_id}", lambda: find_network_acl(ec2, subnet_id))
        subnet["network_acl_id"] = (acl or {}).get("network_acl_id")
        if acl:
            shared["network_acls"].setdefault(acl["network_acl_id"], acl)
    return shared


# Collect every DB instance, cluster, proxy, and manual snapshot in one region plus shared context.
def scan_region(session: Any, region: str) -> dict[str, Any]:
    rds = session.client("rds", region_name=region)
    errors: dict[str, str] = {}

    raw_instances = _try(
        errors, "db_instances", lambda: paginate(rds, "describe_db_instances", "DBInstances")
    ) or []
    raw_clusters = _try(
        errors, "db_clusters", lambda: paginate(rds, "describe_db_clusters", "DBClusters")
    ) or []
    raw_proxies = _try(
        errors, "db_proxies", lambda: paginate(rds, "describe_db_proxies", "DBProxies")
    ) or []
    instances = [_instance(item, region) for item in raw_instances]
    clusters = [_cluster(item, region) for item in raw_clusters]
    proxies = [_proxy(item, region) for item in raw_proxies]
    snapshots = _snapshots(rds, region, errors)

    instance_groups = {
        group["DBParameterGroupName"]
        for item in raw_instances
        for group in item.get("DBParameterGroups", [])
        if group.get("DBParameterGroupName")
    }
    cluster_groups = {
        item["DBClusterParameterGroup"]
        for item in raw_clusters
        if item.get("DBClusterParameterGroup")
    }
    key_ids = {
        item["kms_key_id"] for item in instances + clusters + snapshots if item.get("kms_key_id")
    }

    shared = _network(session, rds, region, instances + clusters + proxies, errors)
    shared["parameter_groups"] = _parameter_groups(
        rds, region, instance_groups, errors, cluster=False
    )
    shared["cluster_parameter_groups"] = _parameter_groups(
        rds, region, cluster_groups, errors, cluster=True
    )
    shared["kms_keys"] = _kms_keys(session, region, key_ids, errors)

    return {
        "region": region,
        "shared": shared,
        "db_instances": instances,
        "db_clusters": clusters,
        "db_proxies": proxies,
        "snapshots": snapshots,
        "collection_errors": errors or None,
    }
