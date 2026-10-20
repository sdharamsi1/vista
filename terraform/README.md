# Test scenarios and answer key

This folder deploys 40 AWS scenarios with Terraform. They are the answer key for comparing Vista
(LLM review) with Prowler (rule-based scanner) on the same resources. The answer key holds facts and
the published severities of AWS Security Hub Foundational Security Best Practices (FSBP) controls
only; it contains no ratings of its own.

Each module under `modules/` (`ec2`, `s3`, `apigateway`, `rds`) creates its scenarios and has a
`ground-truth.json` that is the source of truth. This README is generated from those four files. The
`scenario_resources` Terraform output maps each scenario ID to the resource identifier a tool cites,
which is how a finding is matched to a scenario.

## Fields

- **Tier:** `controlled` scenarios are a ladder of single changes from the module's hardened
  default, one setting per resource. `realistic` scenarios share infrastructure such as a load
  balancer, a NAT gateway, network ACLs, and data stores the way a real account does.
- **Condition:** `flaw` means a misconfiguration was planted; reporting the scenario counts as a
  detection. `flaw_blocked` means a misconfiguration is present but another deployed control
  removes the path it opens; reporting it is shown as a separate report rate, counted as neither a
  detection nor a false positive. `hardened` means no misconfiguration was planted; reporting it is
  a false positive.
- **Context:** deployed facts next to the misconfiguration that narrow or remove what it opens, or
  None.
- **Coverage:** `fsbp` when at least one FSBP control fails because of the scenario's
  configuration, otherwise `outside_fsbp`.
- **FSBP controls:** each entry gives the control ID, its published title, its published severity,
  and the failing resource and setting. A control is attributed to a scenario when it fails because
  of a setting in which the scenario differs from its module's hardened default, or because of a
  resource its configuration associates with it (EC2: its security groups, its subnet's network
  ACL, its IAM role, and the load balancer, listeners, and target group it is registered with; S3:
  none beyond the bucket; API Gateway: its stages, routes, and integrations; RDS: its security group
  and parameter group, and for a snapshot its source DB instance). The highest published severity in
  the list is the scenario's `fsbp_severity`.
- **Baseline controls:** FSBP controls known to fail regardless of scenario (for example
  account-level settings, the VPCs the scenario resources run in, settings left at the hardened
  default, and deletion protection, which every resource leaves off so one `terraform destroy`
  removes everything). The lists are not exhaustive. They are listed per module and are in no
  scenario's FSBP list.
- **ATT&CK:** MITRE ATT&CK techniques the misconfiguration maps to.
- **OWASP API:** OWASP API Security Top 10 (2023) entries, for API Gateway scenarios only.

## Coverage groups and conditions

| Module | Scenarios | fsbp | outside_fsbp | flaw | flaw_blocked | hardened |
| --- | --- | --- | --- | --- | --- | --- |
| EC2 | 11 | 8 | 3 | 9 | 1 | 1 |
| S3 | 11 | 7 | 4 | 9 | 0 | 2 |
| API Gateway | 9 | 2 | 7 | 8 | 0 | 1 |
| RDS | 9 | 6 | 3 | 8 | 0 | 1 |
| Total | 40 | 23 | 17 | 34 | 1 | 5 |

## How the scorer uses it

`scripts/score.py` counts a report on a `flaw` scenario as a detection, shows reports on
`flaw_blocked` scenarios as a separate report rate, and counts reports on `hardened` scenarios as
false positives. On `fsbp` scenarios it also compares the reported severity (NONE when the scenario
is not reported) with `fsbp_severity` on the order NONE < LOW < MEDIUM < HIGH < CRITICAL. On
`outside_fsbp` scenarios it scores detection and false positives only.

## EC2 scenarios

### Baseline controls

- EC2.2 VPC default security groups should not allow inbound or outbound traffic (HIGH; Default security group of the prod and legacy VPCs, which keeps its AWS default rules)
- EC2.6 VPC flow logging should be enabled in all VPCs (MEDIUM; No flow logs on the prod and legacy VPCs)
- EC2.10 Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service (MEDIUM; No Amazon EC2 VPC endpoint in the prod and legacy VPCs)
- EC2.55 VPCs should be configured with an interface endpoint for ECR API (MEDIUM; No ECR API interface endpoint in the prod and legacy VPCs)
- EC2.56 VPCs should be configured with an interface endpoint for Docker Registry (MEDIUM; No Docker Registry interface endpoint in the prod and legacy VPCs)
- EC2.57 VPCs should be configured with an interface endpoint for Systems Manager (MEDIUM; No Systems Manager interface endpoint in the prod and legacy VPCs)
- EC2.58 VPCs should be configured with an interface endpoint for Systems Manager Incident Manager Contacts (MEDIUM; No Systems Manager Incident Manager Contacts interface endpoint in the prod and legacy VPCs)
- EC2.60 VPCs should be configured with an interface endpoint for Systems Manager Incident Manager (MEDIUM; No Systems Manager Incident Manager interface endpoint in the prod and legacy VPCs)
- EC2.7 EBS default encryption should be enabled (MEDIUM; Account setting not managed by this Terraform; fails while EBS encryption by default is off, the AWS default; with it on, ec2-01's root volume would be encrypted regardless of Terraform)
- EC2.172 EC2 VPC Block Public Access settings should block internet gateway traffic (MEDIUM; Account setting not managed by this Terraform; fails while VPC Block Public Access is off, the AWS default)
- EC2.182 Block public access settings should be enabled for Amazon EBS snapshots (HIGH; Account setting, per Region, not managed by this Terraform; fails while block public access for EBS snapshots is not enabled in the Region)
- ELB.6 Application, Gateway, and Network Load Balancers should have deletion protection enabled (MEDIUM; Deletion protection off on the storefront Application Load Balancer)
- SSM.1 Amazon EC2 instances should be managed by AWS Systems Manager (MEDIUM; Instances whose hardened default gives no Systems Manager permissions: ec2-01, ec2-02, ec2-03, ec2-04, ec2-09; the result depends on Systems Manager registration at run time)

### ec2-01: Private instance with an unencrypted root volume

- **Resource:** `reporting-worker`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Private instance in a NAT-routed subnet with no public IP, no inbound security-group rules, no IAM role, no key pair, and IMDSv2 required.
- **What is misconfigured:** the root EBS volume is not encrypted.
- **Context:** None.
- **FSBP controls:** EC2.3 Attached Amazon EBS volumes should be encrypted at-rest (MEDIUM; Root EBS volume of the instance is not encrypted). Highest: MEDIUM.
- **ATT&CK:** T1578.001

### ec2-02: Public instance with HTTP and HTTPS open to 0.0.0.0/0

- **Resource:** `marketing-site`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Instance in a subnet routed to an Internet gateway, serving HTTP on port 80, with IMDSv2 required, an encrypted root volume, and no IAM role.
- **What is misconfigured:** the instance has a public IPv4 address and its security group allows TCP 80 and 443 from 0.0.0.0/0.
- **Context:** None.
- **FSBP controls:** EC2.9 Amazon EC2 instances should not have a public IPv4 address (HIGH; Instance has a public IPv4 address). Highest: HIGH.
- **ATT&CK:** T1190

### ec2-03: Private instance with IMDSv1 and a role that reads the uploads bucket

- **Resource:** `image-resizer`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Private instance with no public IP and no inbound rules; its role allows s3:GetObject and s3:ListBucket on one uploads bucket.
- **What is misconfigured:** instance metadata http_tokens is optional, so IMDSv1 requests are accepted.
- **Context:** None.
- **FSBP controls:** EC2.8 EC2 instances should use Instance Metadata Service Version 2 (IMDSv2) (HIGH; Instance metadata http_tokens is optional). Highest: HIGH.
- **ATT&CK:** T1552.005

### ec2-04: Private CI runner whose role can attach any policy to any role

- **Resource:** `ci-runner`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Private instance with no public IP and no inbound rules.
- **What is misconfigured:** its role's inline policy allows iam:AttachRolePolicy and iam:PutRolePolicy on resource *.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1098.003, T1078.004

### ec2-05: Legacy bastion with SSH open to 0.0.0.0/0 and an AdministratorAccess role

- **Resource:** `legacy-bastion`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Instance in the legacy VPC's subnet, which is routed to an Internet gateway and uses the default network ACL.
- **What is misconfigured:** the instance has a public IPv4 address, its security group allows TCP 22 from 0.0.0.0/0 (rule description "SSH - temporary for migration"), and its role has the AWS managed AdministratorAccess policy.
- **Context:** None.
- **FSBP controls:** EC2.19 Security groups should not allow unrestricted access to ports with high risk (CRITICAL; Instance security group allows TCP 22 from 0.0.0.0/0; 22 is in the control's blockedPorts); EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports (HIGH; Same rule; 22 is not an authorized port (default 80 and 443)); EC2.9 Amazon EC2 instances should not have a public IPv4 address (HIGH; Instance has a public IPv4 address). Highest: CRITICAL.
- **ATT&CK:** T1110, T1021.004, T1078.004

### ec2-06: Storefront behind an internet-facing HTTPS load balancer

- **Resource:** `storefront-web`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Private instance with no public IP, IMDSv2 required, an encrypted root volume, the AmazonSSMManagedInstanceCore policy, and the node-exporter security group (TCP 9100 from the VPC CIDR 10.80.0.0/16); it accepts TCP 8080 only from the load balancer's security group and is the target of the default action of the HTTPS:443 listener on the internet-facing Application Load Balancer, which also has an HTTP:80 listener that redirects to HTTPS.
- **What is misconfigured:** the load balancer has access logging off, its HTTPS listener uses security policy ELBSecurityPolicy-TLS13-1-2-2021-06, its HTTP:80 listener does not use HTTPS, and the instance's target group uses HTTP for traffic and health checks.
- **Context:** None.
- **FSBP controls:** ELB.5 Application and Classic Load Balancers logging should be enabled (MEDIUM; Access logging off on the storefront Application Load Balancer); ELB.17 Application and Network Load Balancers with listeners should use recommended security policies (MEDIUM; HTTPS:443 listener uses security policy ELBSecurityPolicy-TLS13-1-2-2021-06, which is not in the control's sslPolicies list); ELB.18 Application and Network Load Balancer listeners should use secure protocols to encrypt data in transit (MEDIUM; HTTP:80 listener (redirect to HTTPS) does not use HTTPS); ELB.21 Application and Network Load Balancer target groups should use encrypted health check protocols (MEDIUM; storefront target group health check protocol is HTTP); ELB.22 ELB target groups should use encrypted transport protocols (MEDIUM; storefront target group protocol is HTTP). Highest: MEDIUM.
- **ATT&CK:** None.

### ec2-07: Internet-reachable orders API with IMDSv1 and a role that reads every secret

- **Resource:** `orders-api`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Private instance with no public IP and the node-exporter security group (TCP 9100 from the VPC CIDR 10.80.0.0/16) that accepts TCP 8080 only from the load balancer's security group and is the target of the /api/* rule on the same load balancer's HTTPS:443 listener; its role has AmazonSSMManagedInstanceCore and four DynamoDB actions on the orders table.
- **What is misconfigured:** instance metadata http_tokens is optional; the role allows secretsmanager:GetSecretValue and secretsmanager:DescribeSecret on resource *; the load balancer has access logging off, uses ELBSecurityPolicy-TLS13-1-2-2021-06 on HTTPS, and has an HTTP:80 listener; the instance's target group uses HTTP for traffic and health checks.
- **Context:** None.
- **FSBP controls:** EC2.8 EC2 instances should use Instance Metadata Service Version 2 (IMDSv2) (HIGH; Instance metadata http_tokens is optional); ELB.5 Application and Classic Load Balancers logging should be enabled (MEDIUM; Access logging off on the storefront Application Load Balancer); ELB.17 Application and Network Load Balancers with listeners should use recommended security policies (MEDIUM; HTTPS:443 listener uses security policy ELBSecurityPolicy-TLS13-1-2-2021-06, which is not in the control's sslPolicies list); ELB.18 Application and Network Load Balancer listeners should use secure protocols to encrypt data in transit (MEDIUM; HTTP:80 listener (redirect to HTTPS) does not use HTTPS); ELB.21 Application and Network Load Balancer target groups should use encrypted health check protocols (MEDIUM; orders target group health check protocol is HTTP); ELB.22 ELB target groups should use encrypted transport protocols (MEDIUM; orders target group protocol is HTTP). Highest: HIGH.
- **ATT&CK:** T1190, T1552.005, T1555.006

### ec2-08: Public bastion with SSH limited to the office network

- **Resource:** `admin-bastion`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Instance in the ops subnet, which is routed to an Internet gateway and has a custom network ACL, with the AmazonSSMManagedInstanceCore policy and no key pair.
- **What is misconfigured:** the instance has a public IPv4 address, its security group allows TCP 22 from the office CIDR, and the ops network ACL allows all inbound traffic from 0.0.0.0/0 except TCP 9100.
- **Context:** The security group's only inbound rule allows TCP 22 from var.office_cidr (default 203.0.113.0/24, the RFC 5737 TEST-NET-3 range).
- **FSBP controls:** EC2.9 Amazon EC2 instances should not have a public IPv4 address (HIGH; Instance has a public IPv4 address); EC2.21 Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389 (MEDIUM; Ops subnet custom network ACL rule 100 allows all protocols from 0.0.0.0/0, which includes TCP 22). Highest: HIGH.
- **ATT&CK:** T1021.004

### ec2-09: Security group opens 9100 to the world, but the subnet's network ACL denies it

- **Resource:** `metrics-collector`
- **Tier:** realistic
- **Condition:** flaw_blocked
- **Coverage:** fsbp
- **What it is:** Instance in the ops subnet with no IAM role.
- **What is misconfigured:** the instance has a public IPv4 address, its security group allows TCP 9100 from 0.0.0.0/0, and the ops network ACL's rule 100 allows all other inbound traffic from 0.0.0.0/0.
- **Context:** The ops subnet's network ACL rule 90 denies inbound TCP 9100 from 0.0.0.0/0 before rule 100 allows all other traffic; the security group has no other inbound rule.
- **FSBP controls:** EC2.9 Amazon EC2 instances should not have a public IPv4 address (HIGH; Instance has a public IPv4 address); EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports (HIGH; Instance security group allows TCP 9100 from 0.0.0.0/0; 9100 is not an authorized port (default 80 and 443)); EC2.21 Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389 (MEDIUM; Ops subnet custom network ACL rule 100 allows all protocols from 0.0.0.0/0, which includes TCP 22). Highest: HIGH.
- **ATT&CK:** None.

### ec2-10: Private notebook open to 10.0.0.0/8 with s3:* on every bucket

- **Resource:** `analytics-notebook`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Private instance with no public IP and the AmazonSSMManagedInstanceCore policy.
- **What is misconfigured:** its security group allows TCP 8888 (rule description "Jupyter") from 10.0.0.0/8 while the VPC is 10.80.0.0/16, and its role's inline policy data-access allows s3:* on resource *.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1530, T1485

### ec2-11: Private queue worker scoped to one SQS queue

- **Resource:** `queue-worker`
- **Tier:** realistic
- **Condition:** hardened
- **Coverage:** outside_fsbp
- **What it is:** Private instance with no public IP, IMDSv2 required, an encrypted root volume, and the node-exporter security group (TCP 9100 from the VPC CIDR 10.80.0.0/16); its role has AmazonSSMManagedInstanceCore and sqs:ReceiveMessage, sqs:DeleteMessage, and sqs:GetQueueAttributes on one queue.
- **What is misconfigured:** Nothing; hardened.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

## S3 scenarios

### Baseline controls

- S3.1 S3 general purpose buckets should have block public access settings enabled (MEDIUM; Account setting; account-level Block Public Access cannot be fully on, otherwise the public bucket policies and ACL in s3-02 and s3-04 to s3-08 could not be applied)
- S3.13 S3 general purpose buckets should have Lifecycle configurations (LOW; No Lifecycle configuration on any scenario bucket)

### s3-01: CORS allows any origin to send GET, PUT, and DELETE

- **Resource:** `design-assets`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Bucket with the module's hardened settings.
- **What is misconfigured:** its CORS rule allows origin * to send GET, PUT, and DELETE requests with any header.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

### s3-02: public-read ACL lets anyone list object names

- **Resource:** `build-artifacts`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with SSE-KMS, versioning, server access logging, a TLS-only policy, and object ownership BucketOwnerPreferred.
- **What is misconfigured:** the bucket ACL is public-read (an AllUsers READ grant) and its BlockPublicAcls and IgnorePublicAcls settings are off.
- **Context:** The AllUsers grant is READ on the bucket, which permits listing object keys; neither the grant nor the bucket policy grants reading object data.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket ACL grants AllUsers READ while BlockPublicAcls and IgnorePublicAcls are off); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicAcls and IgnorePublicAcls are off); S3.12 ACLs should not be used to manage user access to S3 general purpose buckets (MEDIUM; Bucket ACL (public-read) grants access; object ownership is BucketOwnerPreferred). Highest: CRITICAL.
- **ATT&CK:** T1619

### s3-03: Wildcard principal can read and write objects from any account in the organization

- **Resource:** `shared-datasets`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Bucket with the module's hardened settings.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject and s3:PutObject on all objects, with the condition aws:PrincipalOrgID equal to var.org_id.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1530, T1565.001

### s3-04: Bucket policy allows anonymous s3:GetObject

- **Resource:** `customer-exports`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with SSE-KMS, versioning, server access logging, ACLs disabled, and a TLS-only policy.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject on all objects with no condition, and its BlockPublicPolicy and RestrictPublicBuckets settings are off.
- **Context:** None.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket policy allows Principal * s3:GetObject with no condition); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicPolicy and RestrictPublicBuckets are off). Highest: CRITICAL.
- **ATT&CK:** T1530

### s3-05: Bucket policy allows anonymous read, write, and delete

- **Resource:** `partner-uploads`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with SSE-KMS, versioning, server access logging, ACLs disabled, and a TLS-only policy.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject, s3:PutObject, and s3:DeleteObject on all objects with no condition, and its BlockPublicPolicy and RestrictPublicBuckets settings are off.
- **Context:** None.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket policy allows Principal * s3:GetObject with no condition); S3.3 S3 general purpose buckets should block public write access (CRITICAL; Bucket policy allows Principal * s3:PutObject and s3:DeleteObject with no condition); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicPolicy and RestrictPublicBuckets are off). Highest: CRITICAL.
- **ATT&CK:** T1530, T1565.001, T1485

### s3-06: Static website bucket with anonymous read

- **Resource:** `www`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with static website hosting (index.html, error.html), SSE-S3 (AES256), versioning, server access logging, and ACLs disabled.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject on all objects with no condition, its BlockPublicPolicy and RestrictPublicBuckets settings are off, and the policy has no statement denying non-TLS requests.
- **Context:** Static website hosting is enabled on the bucket; Amazon S3 website endpoints do not support HTTPS.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket policy allows Principal * s3:GetObject with no condition); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicPolicy and RestrictPublicBuckets are off); S3.5 S3 general purpose buckets should require requests to use TLS (MEDIUM; Bucket policy has no statement requiring aws:SecureTransport). Highest: CRITICAL.
- **ATT&CK:** T1530

### s3-07: Anonymous read limited to the public/ prefix

- **Resource:** `media-library`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with SSE-S3, versioning, server access logging, ACLs disabled, and a TLS-only policy.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject on objects under the public/ prefix with no condition, and its BlockPublicPolicy and RestrictPublicBuckets settings are off.
- **Context:** The anonymous grant covers only objects whose keys begin with public/.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket policy allows Principal * s3:GetObject on public/* with no condition); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicPolicy and RestrictPublicBuckets are off). Highest: CRITICAL.
- **ATT&CK:** T1530

### s3-08: Anonymous read restricted only by aws:Referer

- **Resource:** `invoices`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with SSE-S3, versioning, server access logging, ACLs disabled, and a TLS-only policy.
- **What is misconfigured:** its policy allows Principal * to call s3:GetObject on all objects with only an aws:Referer StringLike condition (https://www.<var.name>.example/*, var.name default brightpath), and its BlockPublicPolicy and RestrictPublicBuckets settings are off.
- **Context:** None.
- **FSBP controls:** S3.2 S3 general purpose buckets should block public read access (CRITICAL; Bucket policy allows Principal * s3:GetObject with only an aws:Referer StringLike condition, which contains a wildcard; the control does not evaluate conditions that use wildcards); S3.8 S3 general purpose buckets should block public access (HIGH; BlockPublicPolicy and RestrictPublicBuckets are off). Highest: CRITICAL.
- **ATT&CK:** T1530

### s3-09: Fully hardened application configuration bucket

- **Resource:** `app-config`
- **Tier:** realistic
- **Condition:** hardened
- **Coverage:** outside_fsbp
- **What it is:** Bucket with all four Block Public Access settings on, ACLs disabled (BucketOwnerEnforced), SSE-KMS, versioning, server access logging, and a policy denying non-TLS requests.
- **What is misconfigured:** Nothing; hardened.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

### s3-10: Fully hardened backup bucket with Object Lock

- **Resource:** `db-backups`
- **Tier:** realistic
- **Condition:** hardened
- **Coverage:** outside_fsbp
- **What it is:** Bucket with the same settings as app-config plus Object Lock enabled, with no default retention.
- **What is misconfigured:** Nothing; hardened.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

### s3-11: Private scratch bucket without versioning or access logging

- **Resource:** `tmp-scratch`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Bucket with all four Block Public Access settings on, ACLs disabled, SSE-KMS, and a TLS-only policy.
- **What is misconfigured:** versioning is not enabled and server access logging is off.
- **Context:** None.
- **FSBP controls:** S3.9 S3 general purpose buckets should have server access logging enabled (MEDIUM; Server access logging is off). Highest: MEDIUM.
- **ATT&CK:** None.

## API Gateway scenarios

### Baseline controls

- APIGateway.2 API Gateway REST API stages should be configured to use SSL certificates for backend authentication (MEDIUM; No client certificate for backend authentication on the prod stage of all eight REST APIs)
- APIGateway.3 API Gateway REST API stages should have AWS X-Ray tracing enabled (LOW; X-Ray tracing off on the prod stage of all eight REST APIs)

### apigw-01: IAM-authenticated API with no access logging

- **Resource:** `inventory-api`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API whose GET /items route uses AWS_IAM authorization and calls DynamoDB Scan on the shared table through an execution role limited to that action, with request validation, a WAF web ACL on stage prod, stage throttling (rate 25, burst 50), and execution logging at ERROR.
- **What is misconfigured:** the prod stage has no access log destination.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.
- **OWASP API:** API8:2023

### apigw-02: Execution logging records full request and response bodies

- **Resource:** `support-tickets-api`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API whose GET /items route uses AWS_IAM authorization and calls DynamoDB Scan on the shared table through an execution role limited to that action, with request validation, a WAF web ACL on stage prod, stage throttling (rate 25, burst 50), and access logging.
- **What is misconfigured:** method settings for */* set dataTraceEnabled true and logging level INFO.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.
- **OWASP API:** API8:2023

### apigw-03: IAM-authenticated API with no WAF and no throttling

- **Resource:** `reporting-api`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Regional REST API whose GET /items route uses AWS_IAM authorization and calls DynamoDB Scan on the shared table through an execution role limited to that action, with request validation, access logging, and execution logging at ERROR on stage prod.
- **What is misconfigured:** the prod stage has no WAF web ACL, and method settings set the throttling rate and burst limits to -1 (no stage throttle).
- **Context:** None.
- **FSBP controls:** APIGateway.4 API Gateway should be associated with a WAF Web ACL (MEDIUM; prod stage has no WAF web ACL). Highest: MEDIUM.
- **ATT&CK:** T1499.003
- **OWASP API:** API4:2023

### apigw-04: Route with no authorization reads the DynamoDB table

- **Resource:** `orders-api`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API deployed to stage prod with a WAF web ACL, stage throttling, request validation, and access and execution logging.
- **What is misconfigured:** GET /items has authorization type NONE and calls DynamoDB Scan on the shared table through the execution role.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.
- **OWASP API:** API2:2023

### apigw-05: Routes with no authorization read, write, and delete DynamoDB items

- **Resource:** `loyalty-points-api`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API deployed to stage prod with a WAF web ACL, stage throttling, request validation, and access and execution logging.
- **What is misconfigured:** GET, PUT, and DELETE /items have authorization type NONE and call DynamoDB Scan, PutItem, and DeleteItem through the execution role.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1485, T1565.001
- **OWASP API:** API2:2023, API5:2023

### apigw-06: Cognito-protected API with an anonymous MOCK health check

- **Resource:** `customer-api`
- **Tier:** realistic
- **Condition:** hardened
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API whose GET and PUT /items routes use a Cognito user pool authorizer, with a WAF web ACL, stage throttling, request validation, and access and execution logging; GET /health has authorization type NONE and a MOCK integration that returns a fixed response without calling a backend.
- **What is misconfigured:** Nothing; hardened.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.
- **OWASP API:** None.

### apigw-07: Partner API whose routes require only an API key

- **Resource:** `partner-api`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API with a usage plan (rate 10, burst 20, quota 100,000 requests per month) and one API key, plus a WAF web ACL, stage throttling, and logging.
- **What is misconfigured:** GET and PUT /items have authorization type NONE with api_key_required true, and call DynamoDB Scan and PutItem through the execution role.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1565.001
- **OWASP API:** API2:2023

### apigw-08: Unauthenticated admin API restricted to the office IP range

- **Resource:** `internal-admin-api`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** Regional REST API deployed to stage prod with a WAF web ACL, stage throttling, request validation, and access and execution logging.
- **What is misconfigured:** GET and DELETE /items have authorization type NONE and call DynamoDB Scan and DeleteItem through the execution role.
- **Context:** The REST API resource policy allows execute-api:Invoke for Principal * and explicitly denies it when aws:SourceIp is not in var.office_cidr (default 203.0.113.0/24).
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1485
- **OWASP API:** API2:2023, API5:2023

### apigw-09: HTTP API webhook route with no authorization that writes to SQS

- **Resource:** `webhooks`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** HTTP API whose route POST /webhooks/payments has an AWS_PROXY integration (SQS-SendMessage) that sends the request body to an SQS queue through a role limited to sqs:SendMessage on that queue; the $default stage has route throttling (rate 10, burst 20) and access logging.
- **What is misconfigured:** the route has authorization type NONE.
- **Context:** None.
- **FSBP controls:** APIGateway.8 API Gateway routes should specify an authorization type (MEDIUM; Route POST /webhooks/payments has authorization type NONE). Highest: MEDIUM.
- **ATT&CK:** T1565.001
- **OWASP API:** API2:2023

## RDS scenarios

### Baseline controls

- RDS.5 RDS DB instances should be configured with multiple Availability Zones (MEDIUM; Every DB instance is single-AZ)
- RDS.6 Enhanced monitoring should be configured for RDS DB instances (LOW; Enhanced monitoring off on every DB instance)
- RDS.8 RDS DB instances should have deletion protection enabled (LOW; Deletion protection off on every DB instance)
- RDS.23 RDS instances should not use a database engine default port (LOW; Every DB instance uses its engine's default port (5432 or 3306))
- EC2.2 VPC default security groups should not allow inbound or outbound traffic (HIGH; Default security group of the data VPC, which keeps its AWS default rules)
- EC2.6 VPC flow logging should be enabled in all VPCs (MEDIUM; No flow logs on the data VPC)
- EC2.10 Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service (MEDIUM; No Amazon EC2 VPC endpoint in the data VPC)
- EC2.55 VPCs should be configured with an interface endpoint for ECR API (MEDIUM; No ECR API interface endpoint in the data VPC)
- EC2.56 VPCs should be configured with an interface endpoint for Docker Registry (MEDIUM; No Docker Registry interface endpoint in the data VPC)
- EC2.57 VPCs should be configured with an interface endpoint for Systems Manager (MEDIUM; No Systems Manager interface endpoint in the data VPC)
- EC2.58 VPCs should be configured with an interface endpoint for Systems Manager Incident Manager Contacts (MEDIUM; No Systems Manager Incident Manager Contacts interface endpoint in the data VPC)
- EC2.60 VPCs should be configured with an interface endpoint for Systems Manager Incident Manager (MEDIUM; No Systems Manager Incident Manager interface endpoint in the data VPC)

### rds-01: Private instance with unencrypted storage

- **Resource:** `analytics-db`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** PostgreSQL instance in the private subnet group with publicly_accessible false, no inbound security-group rule, rds.force_ssl 1, IAM authentication, a Secrets Manager managed password, 7-day backups, and log exports.
- **What is misconfigured:** storage is not encrypted.
- **Context:** None.
- **FSBP controls:** RDS.3 RDS DB instances should have encryption at-rest enabled (MEDIUM; Storage is not encrypted). Highest: MEDIUM.
- **ATT&CK:** T1578.001

### rds-02: Private instance that does not enforce TLS

- **Resource:** `billing-db`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** PostgreSQL instance in the private subnet group with publicly_accessible false, no inbound security-group rule, customer-managed KMS encryption, IAM authentication, a Secrets Manager managed password, 7-day backups, and log exports.
- **What is misconfigured:** the parameter group sets rds.force_ssl to 0.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** T1040

### rds-03: Private instance with an associated role that writes to the exports bucket

- **Resource:** `events-db`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** outside_fsbp
- **What it is:** PostgreSQL instance in the private subnet group with publicly_accessible false, no inbound security-group rule, customer-managed KMS encryption, rds.force_ssl 1, IAM authentication, a Secrets Manager managed password, 7-day backups, and log exports.
- **What is misconfigured:** an IAM role whose inline policy allows s3:PutObject and s3:AbortMultipartUpload on the exports bucket's objects is associated with the instance for feature s3Export.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

### rds-04: Public instance with port 5432 open to 0.0.0.0/0

- **Resource:** `crm-db`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** PostgreSQL instance in the public subnet group, whose subnets have a 0.0.0.0/0 route to an Internet gateway and use the default network ACL, with encryption, IAM authentication, and a managed password.
- **What is misconfigured:** publicly_accessible is true and its security group allows TCP 5432 from 0.0.0.0/0.
- **Context:** None.
- **FSBP controls:** RDS.2 RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration (CRITICAL; publicly_accessible is true); EC2.19 Security groups should not allow unrestricted access to ports with high risk (CRITICAL; DB security group allows TCP 5432 from 0.0.0.0/0; 5432 is in the control's blockedPorts); RDS.46 RDS DB instances should not be deployed in public subnets with routes to internet gateways (HIGH; Instance is in the public subnet group, whose subnets have a 0.0.0.0/0 route to an Internet gateway); EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports (HIGH; Same rule; 5432 is not an authorized port (default 80 and 443)). Highest: CRITICAL.
- **ATT&CK:** T1110

### rds-05: Unencrypted manual snapshot shared with all AWS accounts

- **Resource:** `staging-db-pre-migration`
- **Tier:** controlled
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** Manual snapshot staging-db-pre-migration of the private PostgreSQL instance staging-db, whose storage is not encrypted.
- **What is misconfigured:** the snapshot is not encrypted and is shared with all AWS accounts.
- **Context:** None.
- **FSBP controls:** RDS.1 RDS snapshot should be private (CRITICAL; Snapshot is shared with all AWS accounts); RDS.4 RDS cluster snapshots and database snapshots should be encrypted at rest (MEDIUM; Snapshot is not encrypted); RDS.3 RDS DB instances should have encryption at-rest enabled (MEDIUM; Source DB instance staging-db storage is not encrypted). Highest: CRITICAL.
- **ATT&CK:** T1537

### rds-06: Hardened orders database reachable only through its proxy

- **Resource:** `orders-db`
- **Tier:** realistic
- **Condition:** hardened
- **Coverage:** outside_fsbp
- **What it is:** PostgreSQL instance in the private subnet group with customer-managed KMS encryption, rds.force_ssl 1, IAM authentication, a managed password, 7-day backups, and log exports; its only inbound rule allows TCP 5432 from the RDS Proxy's security group, and it is the proxy's target.
- **What is misconfigured:** Nothing; hardened.
- **Context:** None.
- **FSBP controls:** None (outside FSBP).
- **ATT&CK:** None.

### rds-07: RDS Proxy with debug logging left on and TLS optional

- **Resource:** `orders-db-proxy`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** RDS Proxy for PostgreSQL in the private subnets in front of orders-db, authenticating to it with the instance's Secrets Manager secret; its security group allows TCP 5432 from the VPC CIDR 10.81.0.0/16.
- **What is misconfigured:** require_tls is false and debug_logging is true.
- **Context:** None.
- **FSBP controls:** RDS.43 RDS DB proxies should require TLS encryption for connections (MEDIUM; Proxy require_tls is false). Highest: MEDIUM.
- **ATT&CK:** T1040

### rds-08: Public database open to a single office IP

- **Resource:** `bi-reporting-db`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** PostgreSQL instance in the public subnet group with encryption, IAM authentication, and a managed password.
- **What is misconfigured:** publicly_accessible is true.
- **Context:** Its security group allows TCP 5432 only from one /32 address, cidrhost(var.office_cidr, 10) (default 203.0.113.10/32).
- **FSBP controls:** RDS.2 RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration (CRITICAL; publicly_accessible is true); RDS.46 RDS DB instances should not be deployed in public subnets with routes to internet gateways (HIGH; Instance is in the public subnet group, whose subnets have a 0.0.0.0/0 route to an Internet gateway). Highest: CRITICAL.
- **ATT&CK:** T1110

### rds-09: Legacy MySQL open to 10.0.0.0/8 with TLS optional, a static password, and 1-day backups

- **Resource:** `legacy-inventory-db`
- **Tier:** realistic
- **Condition:** flaw
- **Coverage:** fsbp
- **What it is:** MySQL instance in the private subnet group with customer-managed KMS encryption.
- **What is misconfigured:** its security group allows TCP 3306 from 10.0.0.0/8 while the VPC is 10.81.0.0/16; require_secure_transport is OFF; the master password is static rather than managed by Secrets Manager; IAM authentication is off; backup retention is 1 day; and no logs are exported.
- **Context:** None.
- **FSBP controls:** RDS.9 RDS DB instances should publish logs to CloudWatch Logs (MEDIUM; No logs are exported to CloudWatch Logs); RDS.10 IAM authentication should be configured for RDS instances (MEDIUM; IAM database authentication is off); RDS.11 RDS instances should have automatic backups enabled (MEDIUM; Backup retention is 1 day, below the control's default minimum of 7 days). Highest: MEDIUM.
- **ATT&CK:** T1040
