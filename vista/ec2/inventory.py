"""Collect factual EC2 instance inventory."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator

SOURCE_API = "ec2:DescribeInstances"


# Convert a datetime (or other value) to an ISO 8601 string, passing through None.
def isoformat(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


# Flatten AWS key/value tag pairs into a simple {key: value} dict.
def normalize_tags(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {tag["Key"]: tag.get("Value", "") for tag in tags or [] if "Key" in tag}


# Reduce a raw ENI to its addresses, security groups, and attachment details.
def normalize_interface(interface: dict[str, Any]) -> dict[str, Any]:
    public_addresses = set()
    private_addresses = []
    for address in interface.get("PrivateIpAddresses", []):
        public_ip = (address.get("Association") or {}).get("PublicIp")
        if public_ip:
            public_addresses.add(public_ip)
        private_addresses.append(
            {
                "address": address.get("PrivateIpAddress"),
                "primary": address.get("Primary", False),
                "public_ipv4": public_ip,
            }
        )

    attachment = interface.get("Attachment") or {}
    return {
        "network_interface_id": interface.get("NetworkInterfaceId"),
        "interface_type": interface.get("InterfaceType"),
        "status": interface.get("Status"),
        "vpc_id": interface.get("VpcId"),
        "subnet_id": interface.get("SubnetId"),
        "private_ipv4_addresses": private_addresses,
        "public_ipv4_addresses": sorted(public_addresses),
        "ipv6_addresses": sorted(
            item["Ipv6Address"]
            for item in interface.get("Ipv6Addresses", [])
            if item.get("Ipv6Address")
        ),
        "security_group_ids": sorted(
            group["GroupId"]
            for group in interface.get("Groups", [])
            if group.get("GroupId")
        ),
        "attachment": {
            "attachment_id": attachment.get("AttachmentId"),
            "device_index": attachment.get("DeviceIndex"),
            "status": attachment.get("Status"),
            "delete_on_termination": attachment.get("DeleteOnTermination"),
        },
    }


# Reduce a block-device mapping to its device name and EBS attachment facts.
def normalize_block_device(mapping: dict[str, Any]) -> dict[str, Any]:
    ebs = mapping.get("Ebs") or {}
    return {
        "device_name": mapping.get("DeviceName"),
        "volume_id": ebs.get("VolumeId"),
        "attachment_status": ebs.get("Status"),
        "attach_time": isoformat(ebs.get("AttachTime")),
        "delete_on_termination": ebs.get("DeleteOnTermination"),
    }


# Build the normalized instance record (identity, compute, network, IMDS, IAM, storage) from a raw instance.
def normalize_instance(
    instance: dict[str, Any], account_id: str, partition: str, region: str
) -> dict[str, Any]:
    instance_id = instance["InstanceId"]
    placement = instance.get("Placement") or {}
    metadata = instance.get("MetadataOptions") or {}
    profile = instance.get("IamInstanceProfile") or {}
    launch_template = instance.get("LaunchTemplate") or {}
    tags = normalize_tags(instance.get("Tags"))
    interfaces = [
        normalize_interface(interface)
        for interface in instance.get("NetworkInterfaces", [])
    ]

    top_level_public_ip = instance.get("PublicIpAddress")
    if top_level_public_ip and interfaces:
        primary = min(
            interfaces,
            key=lambda item: item["attachment"].get("device_index")
            if item["attachment"].get("device_index") is not None
            else 999,
        )
        if top_level_public_ip not in primary["public_ipv4_addresses"]:
            primary["public_ipv4_addresses"].append(top_level_public_ip)
            primary["public_ipv4_addresses"].sort()

    return {
        "instance_id": instance_id,
        "arn": f"arn:{partition}:ec2:{region}:{account_id}:instance/{instance_id}",
        "account_id": account_id,
        "region": region,
        "name": tags.get("Name"),
        "tags": tags,
        "lifecycle": {
            "state": (instance.get("State") or {}).get("Name"),
            "state_transition_reason": instance.get("StateTransitionReason"),
            "launch_time": isoformat(instance.get("LaunchTime")),
        },
        "compute": {
            "instance_type": instance.get("InstanceType"),
            "image_id": instance.get("ImageId"),
            "architecture": instance.get("Architecture"),
            "platform_details": instance.get("PlatformDetails"),
            "availability_zone": placement.get("AvailabilityZone"),
            "tenancy": placement.get("Tenancy"),
            "key_name": instance.get("KeyName"),
            "source_dest_check": instance.get("SourceDestCheck"),
            "monitoring_state": (instance.get("Monitoring") or {}).get("State"),
            "launch_template": {
                "id": launch_template.get("LaunchTemplateId"),
                "name": launch_template.get("LaunchTemplateName"),
                "version": launch_template.get("Version"),
            },
        },
        "network": {
            "vpc_id": instance.get("VpcId"),
            "primary_subnet_id": instance.get("SubnetId"),
            "private_dns_name": instance.get("PrivateDnsName"),
            "public_dns_name": instance.get("PublicDnsName"),
            "interfaces": interfaces,
        },
        "instance_metadata": {
            "state": metadata.get("State"),
            "endpoint": metadata.get("HttpEndpoint"),
            "http_tokens": metadata.get("HttpTokens"),
            "hop_limit": metadata.get("HttpPutResponseHopLimit"),
            "ipv6_endpoint": metadata.get("HttpProtocolIpv6"),
            "tags_in_metadata": metadata.get("InstanceMetadataTags"),
        },
        "iam": {
            "instance_profile_arn": profile.get("Arn"),
            "instance_profile_id": profile.get("Id"),
        },
        "storage": {
            "root_device_name": instance.get("RootDeviceName"),
            "root_device_type": instance.get("RootDeviceType"),
            "block_devices": [
                normalize_block_device(mapping)
                for mapping in instance.get("BlockDeviceMappings", [])
            ],
        },
    }


# Paginate DescribeInstances and yield a normalized record for every non-terminated instance.
def discover_instances(
    ec2_client: Any, account_id: str, partition: str, region: str
) -> Iterator[dict[str, Any]]:
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if (instance.get("State") or {}).get("Name") != "terminated":
                    yield normalize_instance(instance, account_id, partition, region)
