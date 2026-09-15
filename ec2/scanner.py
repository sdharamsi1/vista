"""Orchestrate factual EC2 collectors."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from ec2.iam import SOURCE_APIS as IAM_APIS
from ec2.iam import enrich_iam
from ec2.inventory import SOURCE_API as INVENTORY_API
from ec2.inventory import discover_instances
from ec2.load_balancers import SOURCE_APIS as LOAD_BALANCER_APIS
from ec2.load_balancers import enrich_load_balancers
from ec2.network import SOURCE_APIS as NETWORK_APIS
from ec2.network import enrich_network
from ec2.storage import SOURCE_API as STORAGE_API
from ec2.storage import enrich_storage


# Normalize a boto exception into a structured dict recording the failure details.
def error_details(error: BotoCoreError | ClientError) -> dict[str, Any]:
    if isinstance(error, ClientError):
        details = error.response.get("Error", {})
        return {
            "type": type(error).__name__,
            "code": details.get("Code"),
            "message": details.get("Message"),
            "operation": error.operation_name,
        }
    return {"type": type(error).__name__, "message": str(error)}


# Run one collector on a copy of the resources, committing results and recording SUCCESS/ERROR status.
def run_collector(
    name: str,
    source_apis: list[str],
    resources: list[dict[str, Any]],
    operation: Callable[[list[dict[str, Any]]], None],
    statuses: dict[str, dict[str, Any]],
) -> None:
    candidate = deepcopy(resources)
    try:
        operation(candidate)
        resources[:] = candidate
        statuses[name] = {"status": "SUCCESS", "source_apis": source_apis}
    except (BotoCoreError, ClientError) as error:
        statuses[name] = {
            "status": "ERROR",
            "source_apis": source_apis,
            "error": error_details(error),
        }


# Discover instances and run every enrichment collector, returning the full factual payload.
def scan_region(session: Any, region: str) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    caller = session.client("sts").get_caller_identity()
    account_id = caller["Account"]
    partition = caller["Arn"].split(":", 2)[1]
    ec2_client = session.client("ec2", region_name=region)
    instances = list(discover_instances(ec2_client, account_id, partition, region))
    statuses = {
        "identity": {
            "status": "SUCCESS",
            "source_apis": ["sts:GetCallerIdentity"],
        },
        "inventory": {"status": "SUCCESS", "source_apis": [INVENTORY_API]},
    }

    collectors = [
        ("network", NETWORK_APIS, lambda items: enrich_network(ec2_client, items)),
        ("storage", [STORAGE_API], lambda items: enrich_storage(ec2_client, items)),
        (
            "iam",
            IAM_APIS,
            lambda items: enrich_iam(session.client("iam"), items),
        ),
        (
            "load_balancers",
            LOAD_BALANCER_APIS,
            lambda items: enrich_load_balancers(
                session.client("elbv2", region_name=region), ec2_client, items
            ),
        ),
    ]
    for name, source_apis, operation in collectors:
        run_collector(name, source_apis, instances, operation, statuses)

    return {
        "scan": {
            "account_id": account_id,
            "caller_arn": caller.get("Arn"),
            "region": region,
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "collector_status": statuses,
        },
        "instances": instances,
    }
