"""Collect factual EBS volume configuration."""

from __future__ import annotations

from typing import Any

from vista.ec2.inventory import isoformat, normalize_tags

SOURCE_API = "ec2:DescribeVolumes"


# Fetch and normalize the given EBS volumes (encryption, size, attachments), batching in groups of 200.
def load_volumes(ec2_client: Any, volume_ids: set[str]) -> dict[str, dict[str, Any]]:
    volumes = {}
    ordered_ids = sorted(volume_ids)
    for start in range(0, len(ordered_ids), 200):
        response = ec2_client.describe_volumes(
            VolumeIds=ordered_ids[start : start + 200]
        )
        for volume in response.get("Volumes", []):
            volume_id = volume["VolumeId"]
            volumes[volume_id] = {
                "volume_id": volume_id,
                "state": volume.get("State"),
                "encrypted": volume.get("Encrypted"),
                "kms_key_id": volume.get("KmsKeyId"),
                "size_gib": volume.get("Size"),
                "volume_type": volume.get("VolumeType"),
                "iops": volume.get("Iops"),
                "throughput_mibps": volume.get("Throughput"),
                "snapshot_id": volume.get("SnapshotId"),
                "multi_attach_enabled": volume.get("MultiAttachEnabled"),
                "tags": normalize_tags(volume.get("Tags")),
                "attachments": [
                    {
                        "instance_id": item.get("InstanceId"),
                        "device": item.get("Device"),
                        "state": item.get("State"),
                        "attach_time": isoformat(item.get("AttachTime")),
                        "delete_on_termination": item.get("DeleteOnTermination"),
                    }
                    for item in volume.get("Attachments", [])
                ],
            }
    return volumes


# Attach the resolved volume details to each block device on every instance.
def enrich_storage(ec2_client: Any, resources: list[dict[str, Any]]) -> None:
    volume_ids = {
        device["volume_id"]
        for resource in resources
        for device in resource["storage"]["block_devices"]
        if device.get("volume_id")
    }
    volumes = load_volumes(ec2_client, volume_ids)
    for resource in resources:
        for device in resource["storage"]["block_devices"]:
            device["volume"] = volumes.get(device.get("volume_id"))
