# EC2 Security Review

## Account Risk Summary
All 11 running instances live in us-east-1 across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). Most workloads sit in private subnets behind a NAT gateway or an internet-facing ALB, but one internet-reachable bastion accepts SSH from the entire Internet while carrying an AdministratorAccess role, and several instance roles grant account-wide IAM, S3, or Secrets Manager permissions.

## Top Findings

### 1. Internet-wide SSH to a bastion holding AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** The instance is running with public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has an active 0.0.0.0/0 route to igw-0a2ccf998af2d1439; sg-0521ad17fec26a09a allows tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration") and NACL acl-0b53e66e7bfebf35d allows all ingress/egress. Its instance profile brightpath-legacy-bastion attaches arn:aws:iam::aws:policy/AdministratorAccess (Allow `*` on `*`), last used 2026-10-21T00:18:09Z.
- **Why it matters:** Any host on the Internet can attempt SSH authentication, and success on this instance yields credentials with unrestricted administrative control of account 111122223333.
- **Remediation:** Replace the 0.0.0.0/0 tcp/22 rule in sg-0521ad17fec26a09a with the specific admin CIDRs (or remove inbound SSH and use SSM Session Manager), and detach AdministratorAccess from role brightpath-legacy-bastion in favour of a least-privilege policy.

### 2. Internet-facing ALB target with IMDSv1 enabled and account-wide Secrets Manager read
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** instance_metadata.http_tokens is "optional" (hop_limit 2), so unauthenticated IMDSv1 requests are accepted; the role brightpath-orders-api inline policy "permissions" allows secretsmanager:GetSecretValue and secretsmanager:DescribeSecret on resource `*`. The instance receives Internet traffic from internet-facing ALB brightpath-storefront (state active, HTTPS:443 listener, rule priority 10 path-pattern /api/*) to port 8080 allowed by sg-0bc2a88820fff1ac7 from ALB group sg-0f2ef87dec0737621.
- **Why it matters:** A request-forgery or code-execution flaw in the Internet-exposed /api/* application can read instance credentials without a token and then retrieve every secret in the account.
- **Remediation:** Set http_tokens to "required" on this instance and scope the Secrets Manager statement to the specific secret ARNs the service needs.

### 3. CI runner role can attach or inline any IAM policy (privilege escalation to admin)
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** Instance profile brightpath-ci-runner role inline policy "permissions" allows iam:AttachRolePolicy and iam:PutRolePolicy on resource `*` (role last used 2026-10-21T00:19:50Z). The instance has no public IP and sits in private subnet-0c15f9cb55de4e1b6 (rtb-021f485c86ae5e308 routes 0.0.0.0/0 to nat-0655e4de3667d0e70), and sg-01ee4d1d0c69cd2e9 has no ingress rules.
- **Why it matters:** Anyone who obtains these instance credentials can attach AdministratorAccess to any role and take over the account, so the blast radius is account-wide despite the instance not being directly reachable.
- **Remediation:** Restrict the IAM statement to specific role ARNs with a iam:PermissionsBoundary condition, or remove iam:AttachRolePolicy/iam:PutRolePolicy from role brightpath-ci-runner entirely.

### 4. Analytics notebook role grants s3:* on all buckets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Instance profile brightpath-analytics-notebook role inline policy "data-access" allows s3:* on resource `*` (role last used 2026-10-21T00:20:47Z). sg-037fdf8c5d0449baf allows tcp/8888 ("Jupyter") from 10.0.0.0/8, reachable from any private host in the 10.x space, including the Internet-exposed bastions.
- **Why it matters:** Credentials from this instance permit read, write, and delete of every S3 bucket in the account, including data belonging to other workloads such as brightpath-media-uploads-111122223333.
- **Remediation:** Replace s3:* on `*` with the specific bucket ARNs and actions the notebook requires, and narrow the 8888 ingress source to the exact client CIDR or security group.

### 5. Marketing site instance directly exposed to the Internet on HTTP/HTTPS
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** Running with public IP 100.31.186.21 in subnet-04fd2627f6fae2335, associated route table rtb-0d71f7a82c78aa5af has an active 0.0.0.0/0 route to igw-095e3728c39a3ae65; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0 and NACL acl-09263760a4356cb9b allows all traffic. The instance has no instance profile (iam.instance_profile_arn null) and http_tokens is "required".
- **Why it matters:** The web application is directly reachable from any Internet host, bypassing the ALB; compromise is limited to this instance since it holds no IAM credentials.
- **Remediation:** Place the site behind the existing ALB (or restrict sg-055c437d6b40cde19 to the ALB security group) and remove the public IP so the instance is only reachable through the load balancer.

### 6. Prometheus node-exporter port 9100 open to 0.0.0.0/0 on a public instance, blocked only by a network ACL
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** Public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with an active 0.0.0.0/0 route to igw-095e3728c39a3ae65 (rtb-0d71f7a82c78aa5af); sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0, but NACL acl-0dae44201bff0235a rule 90 denies ingress tcp 9100 from 0.0.0.0/0 ahead of the allow-all rule 100.
- **Why it matters:** Only the subnet NACL stops Internet access to the metrics endpoint; removing or reordering that single rule would expose host telemetry publicly.
- **Remediation:** Change the sg-0e30fd4297eb362e8 ingress source for tcp/9100 to the Prometheus server's security group or 10.80.0.0/16 so the control does not depend on NACL rule 90.

### 7. IMDSv1 permitted on image-resizer instance
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** instance_metadata.http_tokens is "optional" with hop_limit 2; the attached role brightpath-image-resizer is limited to s3:GetObject and s3:ListBucket on arn:aws:s3:::brightpath-media-uploads-111122223333. The instance is in private subnet-0c15f9cb55de4e1b6 with no ingress rules in sg-00e85873169a4dd0b.
- **Why it matters:** Token-less metadata access makes credential theft via server-side request forgery easier, though the stolen credentials only read one media bucket.
- **Remediation:** Set http_tokens to "required" (IMDSv2 only) on this instance.

### 8. Unencrypted root EBS volume
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Root volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has encrypted=false and kms_key_id null, while every other instance's root volume is encrypted with arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest and any snapshots of this volume are stored without KMS encryption, unlike the rest of the fleet.
- **Remediation:** Recreate the instance from an encrypted snapshot (or replace the volume with an encrypted gp3 volume using the existing KMS key) and enable EBS encryption by default in the region.
