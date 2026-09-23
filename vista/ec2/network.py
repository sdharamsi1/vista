"""Collect factual EC2 network configuration."""

from __future__ import annotations

from typing import Any

from vista.ec2.inventory import normalize_tags

SOURCE_APIS = [
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeNetworkAcls",
]


# Flatten a security group's ingress or egress permissions into per-peer rule records.
def normalize_rules(
    security_group: dict[str, Any], direction: str
) -> list[dict[str, Any]]:
    key = "IpPermissions" if direction == "ingress" else "IpPermissionsEgress"
    rules = []
    for permission in security_group.get(key, []):
        protocol = permission.get("IpProtocol")
        common = {
            "protocol": "all" if protocol == "-1" else protocol,
            "from_port": permission.get("FromPort"),
            "to_port": permission.get("ToPort"),
        }
        peers = [
            {
                "type": "ipv4_cidr",
                "value": item.get("CidrIp"),
                "description": item.get("Description"),
            }
            for item in permission.get("IpRanges", [])
        ]
        peers.extend(
            {
                "type": "ipv6_cidr",
                "value": item.get("CidrIpv6"),
                "description": item.get("Description"),
            }
            for item in permission.get("Ipv6Ranges", [])
        )
        peers.extend(
            {
                "type": "security_group",
                "value": item.get("GroupId"),
                "account_id": item.get("UserId"),
                "description": item.get("Description"),
            }
            for item in permission.get("UserIdGroupPairs", [])
        )
        peers.extend(
            {
                "type": "prefix_list",
                "value": item.get("PrefixListId"),
                "description": item.get("Description"),
            }
            for item in permission.get("PrefixListIds", [])
        )
        rules.extend({**common, "peer": peer} for peer in peers)
    return rules


# Fetch and normalize the given security groups, batching the describe calls in groups of 100.
def load_security_groups(
    ec2_client: Any, group_ids: set[str]
) -> dict[str, dict[str, Any]]:
    groups = {}
    ordered_ids = sorted(group_ids)
    for start in range(0, len(ordered_ids), 100):
        response = ec2_client.describe_security_groups(
            GroupIds=ordered_ids[start : start + 100]
        )
        for group in response.get("SecurityGroups", []):
            group_id = group["GroupId"]
            groups[group_id] = {
                "group_id": group_id,
                "group_name": group.get("GroupName"),
                "description": group.get("Description"),
                "vpc_id": group.get("VpcId"),
                "tags": normalize_tags(group.get("Tags")),
                "ingress_rules": normalize_rules(group, "ingress"),
                "egress_rules": normalize_rules(group, "egress"),
            }
    return groups


# Fetch and normalize the given subnets, batching the describe calls in groups of 200.
def load_subnets(ec2_client: Any, subnet_ids: set[str]) -> dict[str, dict[str, Any]]:
    subnets = {}
    ordered_ids = sorted(subnet_ids)
    for start in range(0, len(ordered_ids), 200):
        response = ec2_client.describe_subnets(
            SubnetIds=ordered_ids[start : start + 200]
        )
        for subnet in response.get("Subnets", []):
            subnet_id = subnet["SubnetId"]
            subnets[subnet_id] = {
                "subnet_id": subnet_id,
                "vpc_id": subnet.get("VpcId"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "availability_zone_id": subnet.get("AvailabilityZoneId"),
                "ipv4_cidr": subnet.get("CidrBlock"),
                "ipv6_cidrs": [
                    item.get("Ipv6CidrBlock")
                    for item in subnet.get("Ipv6CidrBlockAssociationSet", [])
                    if item.get("Ipv6CidrBlock")
                ],
                "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch"),
                "assign_ipv6_on_creation": subnet.get("AssignIpv6AddressOnCreation"),
                "default_for_availability_zone": subnet.get("DefaultForAz"),
                "tags": normalize_tags(subnet.get("Tags")),
            }
    return subnets


# Page through DescribeRouteTables for the given filters and return all matching tables.
def describe_route_tables(
    ec2_client: Any, filters: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    tables = []
    paginator = ec2_client.get_paginator("describe_route_tables")
    for page in paginator.paginate(Filters=filters):
        tables.extend(page.get("RouteTables", []))
    return tables


# Identify a route's target type and ID (internet gateway, NAT, transit gateway, etc.).
def route_target(route: dict[str, Any]) -> dict[str, Any]:
    fields = [
        ("GatewayId", "gateway"),
        ("NatGatewayId", "nat_gateway"),
        ("TransitGatewayId", "transit_gateway"),
        ("VpcPeeringConnectionId", "vpc_peering_connection"),
        ("VpcEndpointId", "vpc_endpoint"),
        ("NetworkInterfaceId", "network_interface"),
        ("InstanceId", "instance"),
        ("EgressOnlyInternetGatewayId", "egress_only_internet_gateway"),
        ("CarrierGatewayId", "carrier_gateway"),
        ("LocalGatewayId", "local_gateway"),
        ("CoreNetworkArn", "core_network"),
    ]
    for field, target_type in fields:
        target_id = route.get(field)
        if target_id:
            if field == "GatewayId" and target_id.startswith("igw-"):
                target_type = "internet_gateway"
            elif field == "GatewayId" and target_id.startswith("vgw-"):
                target_type = "virtual_private_gateway"
            return {"type": target_type, "id": target_id}
    return {"type": "unknown", "id": None}


# Reduce a route table to its ID, association type, and normalized routes.
def normalize_route_table(
    route_table: dict[str, Any], association_type: str
) -> dict[str, Any]:
    return {
        "route_table_id": route_table.get("RouteTableId"),
        "vpc_id": route_table.get("VpcId"),
        "association_type": association_type,
        "tags": normalize_tags(route_table.get("Tags")),
        "routes": [
            {
                "destination": route.get("DestinationCidrBlock")
                or route.get("DestinationIpv6CidrBlock")
                or route.get("DestinationPrefixListId"),
                "state": route.get("State"),
                "origin": route.get("Origin"),
                "target": route_target(route),
            }
            for route in route_table.get("Routes", [])
            if route.get("DestinationCidrBlock")
            or route.get("DestinationIpv6CidrBlock")
            or route.get("DestinationPrefixListId")
        ],
    }


# Resolve the route table governing a subnet, preferring an explicit association over the VPC main table.
def find_effective_route_table(
    ec2_client: Any, subnet_id: str | None, vpc_id: str | None
) -> dict[str, Any] | None:
    if not subnet_id or not vpc_id:
        return None
    explicit = describe_route_tables(
        ec2_client, [{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )
    if explicit:
        return normalize_route_table(explicit[0], "explicit_subnet_association")
    main = describe_route_tables(
        ec2_client,
        [
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]},
        ],
    )
    return normalize_route_table(main[0], "main_vpc_route_table") if main else None


# Reduce a network ACL to its associations and ordered ingress/egress entries.
def normalize_network_acl(network_acl: dict[str, Any]) -> dict[str, Any]:
    return {
        "network_acl_id": network_acl.get("NetworkAclId"),
        "vpc_id": network_acl.get("VpcId"),
        "is_default": network_acl.get("IsDefault"),
        "tags": normalize_tags(network_acl.get("Tags")),
        "associations": [
            {
                "association_id": item.get("NetworkAclAssociationId"),
                "subnet_id": item.get("SubnetId"),
            }
            for item in network_acl.get("Associations", [])
        ],
        "entries": [
            {
                "rule_number": entry.get("RuleNumber"),
                "direction": "egress" if entry.get("Egress") else "ingress",
                "action": entry.get("RuleAction"),
                "protocol": entry.get("Protocol"),
                "ipv4_cidr": entry.get("CidrBlock"),
                "ipv6_cidr": entry.get("Ipv6CidrBlock"),
                "port_range": entry.get("PortRange"),
                "icmp": entry.get("IcmpTypeCode"),
            }
            for entry in sorted(
                network_acl.get("Entries", []),
                key=lambda item: (item.get("Egress", False), item.get("RuleNumber", 0)),
            )
        ],
    }


# Look up and normalize the network ACL associated with a subnet, if any.
def find_network_acl(ec2_client: Any, subnet_id: str | None) -> dict[str, Any] | None:
    if not subnet_id:
        return None
    response = ec2_client.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )
    acls = response.get("NetworkAcls", [])
    return normalize_network_acl(acls[0]) if acls else None


# Attach security groups, subnets, effective route tables, and NACLs to each instance's interfaces.
def enrich_network(ec2_client: Any, resources: list[dict[str, Any]]) -> None:
    interfaces = [
        interface
        for resource in resources
        for interface in resource["network"]["interfaces"]
    ]
    groups = load_security_groups(
        ec2_client,
        {group_id for interface in interfaces for group_id in interface["security_group_ids"]},
    )
    subnets = load_subnets(
        ec2_client,
        {interface["subnet_id"] for interface in interfaces if interface.get("subnet_id")},
    )
    route_cache: dict[tuple[str | None, str | None], dict[str, Any] | None] = {}
    acl_cache: dict[str | None, dict[str, Any] | None] = {}

    for resource in resources:
        network = resource["network"]
        group_ids = sorted(
            {
                group_id
                for interface in network["interfaces"]
                for group_id in interface["security_group_ids"]
            }
        )
        network["security_groups"] = [
            groups[group_id] for group_id in group_ids if group_id in groups
        ]
        for interface in network["interfaces"]:
            subnet_id = interface.get("subnet_id")
            route_key = (subnet_id, interface.get("vpc_id"))
            if route_key not in route_cache:
                route_cache[route_key] = find_effective_route_table(
                    ec2_client, *route_key
                )
            if subnet_id not in acl_cache:
                acl_cache[subnet_id] = find_network_acl(ec2_client, subnet_id)
            interface["subnet"] = subnets.get(subnet_id)
            interface["effective_route_table"] = route_cache[route_key]
            interface["network_acl"] = acl_cache[subnet_id]
