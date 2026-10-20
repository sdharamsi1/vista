"""EC2 review spec: the service guidance and response validation for the Bedrock review."""

from __future__ import annotations

from typing import Any

from vista import findings

SPEC = findings.ReviewSpec(
    service="EC2",
    noun="instance",
    categories=("INTERNET_EXPOSURE", "SECURITY_CONFIGURATION"),
    affected_label="Affected instances",
    affected_format="each instance formatted as `i-instanceid` (Name or Unnamed)",
    summary=(
        "One or two sentences on the account's overall EC2 posture, the number of "
        "instances reviewed, and the regions covered."
    ),
)

GUIDANCE = """Review the supplied factual AWS EC2 configuration for one AWS account, which may
span one or more regions. The JSON contains real resource identities and exact AWS API values for
every non-terminated instance in the account. Each instance record includes its own "region" field.
Make all security judgments yourself; no local security conclusions are included.

To avoid duplication, resources shared by multiple instances are de-duplicated into a top-level
"shared" object and referenced by ID from each instance. Resolve every reference before reasoning,
and treat the referenced data as if it were inline on the instance:
- instance.network.security_group_ids and each load balancer's security_group_ids -> shared.security_groups[id]
- each interface's subnet_id -> shared.subnets[id]; route_table_id -> shared.route_tables[id]; network_acl_id -> shared.network_acls[id]
- instance.iam.instance_profile_arn -> shared.instance_profiles[arn]; within a profile, a role's managed policy references shared.managed_policies[arn] (the policy document lives there)
- each load_balancer_relationship's load_balancer_arn -> shared.load_balancers[arn]; target_group_arn -> shared.target_groups[arn]
- load_balancer_relationships[].authentication_actions lists the authenticate-oidc and
  authenticate-cognito actions on the listener rule that forwards to the instance; authentication
  performed inside the application is not collected.
A missing reference means the collector did not return that object, exactly as if it were absent.

Your task: identify the account's most significant EC2 security risks, whether they arise from
Internet exposure or from security configuration, and report only the ones that genuinely matter.
Return at most 10 findings, and fewer when fewer real risks exist. Never manufacture findings to
reach a count. Order findings from most to least severe.

AWS behavior relevant to the supplied fields:
- An instance that is not in the running state does not send or receive network traffic.
- Security groups are stateful and contain only allow rules. Inbound traffic to a network
  interface is allowed when a rule in any security group attached to it matches the traffic's
  protocol, port, and source, and response traffic for an allowed connection is allowed
  automatically. Security-group egress rules control traffic that the instance initiates.
- A security-group rule whose source is another security group matches traffic from the private IP
  addresses of network interfaces that have that group attached. 10.0.0.0/8, 172.16.0.0/12, and
  192.168.0.0/16 are private (RFC 1918) address ranges, which are not routed on the public Internet.
- An instance with a public IPv4 address or an IPv6 address can communicate with the Internet
  through an Internet gateway, and hosts on the Internet can initiate connections to that address,
  only when the route table associated with the instance's subnet has a route to the Internet
  gateway; without that route the instance can't communicate with the Internet even if it has a
  public IP address. A route in the blackhole state has a target that isn't available (for example,
  a gateway that isn't attached to the VPC).
- Network ACLs filter traffic entering and leaving a subnet.
- A NAT gateway lets instances in a private subnet connect to destinations outside the VPC; hosts
  outside the VPC cannot initiate connections to those instances through it. A transit gateway
  routes traffic between the VPCs and networks attached to it.
- Names and tags are user-defined labels; route tables, security groups, and network ACLs do not
  evaluate them.
- A load balancer's scheme is internet-facing or internal. The nodes of an internet-facing load
  balancer have public IP addresses and its DNS name resolves to them, so it can route requests
  from clients over the Internet; the nodes of an internal load balancer have only private IP
  addresses, so it can route only requests from clients with access to its VPC. Security groups
  attached to a load balancer control which sources can connect to its listeners.
- A load balancer's state is provisioning while it is being set up, active when it is set up and
  routing traffic, active_impaired when it is routing traffic but lacks the resources it needs to
  scale, and failed when it could not be set up.
- A listener accepts client connections on its own protocol and port and forwards them to a target
  group, through its default action or, on an Application Load Balancer, through rules evaluated
  by priority and conditions; the target group sends each request to a registered target on the
  target port.
- instance_metadata.http_tokens optional means the instance metadata service accepts IMDSv1
  requests without a session token as well as IMDSv2 requests; required means it accepts only
  IMDSv2 requests that carry a session token.

{SEVERITY_MODEL}

Assign each finding one Category by what it is about: INTERNET_EXPOSURE when it is about network
reachability of instances from the Internet, SECURITY_CONFIGURATION when it is about any other
configuration of the instances or the resources attached to them.

Instances in different regions can share a finding; when a finding spans regions, name each
affected region in the Evidence.
"""


# Every identifier a finding may cite.
def identifiers(facts: dict[str, Any]) -> set[str]:
    return {instance["instance_id"] for instance in facts.get("instances", [])}


# Build the per-request system prompt with the instance count.
def build_system_prompt(facts: dict[str, Any]) -> str:
    counts = f"{len(facts.get('instances', []))} instances"
    return findings.build_system_prompt(SPEC, GUIDANCE, counts)


# Validate the review structure and that every cited instance exists; raise on any defect.
def validate(text: str, facts: dict[str, Any]) -> None:
    findings.validate_review(text, SPEC, identifiers(facts))
