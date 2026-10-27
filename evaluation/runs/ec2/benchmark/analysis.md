# EC2 Security Review

## Account Risk Summary
All 11 running instances live in a single region (us-east-1) across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). The dominant risks are a world-open SSH bastion carrying an AdministratorAccess role, several instance roles with wildcard IAM/S3/Secrets Manager permissions, and two instances still accepting IMDSv1.

## Top Findings

### 1. Legacy bastion exposes SSH to the entire Internet while holding AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1, this running instance has public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has an active 0.0.0.0/0 route to igw-0a2ccf998af2d1439, and acl-0b53e66e7bfebf35d allows all ingress; sg-0521ad17fec26a09a allows tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration"). Its instance profile brightpath-legacy-bastion attaches the managed policy AdministratorAccess (Allow `*` on `*`), last used 2026-10-21T00:18:09Z.
- **Why it matters:** Any Internet host can reach the SSH service, and any code execution on this host yields credentials with unrestricted administrative control of account 111122223333.
- **Remediation:** Remove the 0.0.0.0/0 tcp/22 ingress rule from sg-0521ad17fec26a09a (use SSM Session Manager or restrict to specific corporate CIDRs), and replace AdministratorAccess on role brightpath-legacy-bastion with a least-privilege policy such as AmazonSSMManagedInstanceCore.

### 2. CI runner role can escalate to account administrator via wildcard IAM write permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** The instance profile brightpath-ci-runner contains inline policy "permissions" allowing `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `*` (role last used 2026-10-21T00:19:50Z, us-east-1). The instance is in private subnet-0c15f9cb55de4e1b6 (route table rtb-021f485c86ae5e308 egresses via nat-0655e4de3667d0e70) and sg-01ee4d1d0c69cd2e9 has no ingress rules.
- **Why it matters:** Any process on this instance can attach AdministratorAccess to any role in the account, converting limited instance access into full account takeover.
- **Remediation:** Scope the inline policy's `iam:AttachRolePolicy`/`iam:PutRolePolicy` to specific role ARNs and add a `iam:PermissionsBoundary` condition, or remove these IAM write actions from role brightpath-ci-runner entirely.

### 3. Analytics notebook role grants s3:* on all buckets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Instance profile brightpath-analytics-notebook has inline policy "data-access" allowing `s3:*` on `*` (role last used 2026-10-21T00:20:47Z). The instance sits in private subnet-0c15f9cb55de4e1b6, and sg-037fdf8c5d0449baf exposes tcp/8888 ("Jupyter") to the whole 10.0.0.0/8 range rather than a specific subnet or security group.
- **Why it matters:** Access to the notebook — reachable from any RFC1918 10/8 address with VPC connectivity — yields read, write, and delete over every S3 bucket in the account, including data belonging to other workloads.
- **Remediation:** Replace `s3:*` on `*` with the specific bucket ARNs and actions the notebook requires, and narrow the sg-037fdf8c5d0449baf port 8888 source to the specific client CIDR or security group.

### 4. Orders API role can read every secret in the account
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** Instance profile brightpath-orders-api allows `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `*` (role last used 2026-10-21T00:24:26Z). The instance is a healthy target on port 8080 of the internet-facing, active ALB brightpath-storefront (listener HTTPS:443, rule priority 10, path-pattern `/api/*`), reached through sg-0bc2a88820fff1ac7 allowing tcp/8080 from the ALB group sg-0f2ef87dec0737621, which accepts 80/443 from 0.0.0.0/0.
- **Why it matters:** The application is Internet-reachable, and any code execution or credential exposure on it grants read access to all Secrets Manager secrets in account 111122223333, not just the orders workload's own.
- **Remediation:** Restrict the Secrets Manager statement to the specific secret ARNs this service needs, leaving no wildcard resource for `secretsmanager:GetSecretValue`.

### 5. IMDSv1 still accepted on two instances with IAM roles
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api), `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** Both us-east-1 instances have instance_metadata.http_tokens = "optional" with endpoint enabled and hop_limit 2, and both have instance profiles attached (brightpath-orders-api with wildcard Secrets Manager read; brightpath-image-resizer with s3:GetObject/ListBucket on brightpath-media-uploads-111122223333). i-0fac06eba5d0109a7 also serves traffic from the internet-facing ALB brightpath-storefront.
- **Why it matters:** IMDSv1 allows unauthenticated, tokenless metadata requests, so a server-side request forgery or proxy flaw in the application can retrieve the instance role's temporary credentials.
- **Remediation:** Set metadata options to http_tokens = "required" (IMDSv2 only) on both instances and keep hop_limit at 1 where no container networking requires 2.

### 6. Marketing site instance directly exposed to the Internet on ports 80 and 443
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** In us-east-1 the running instance holds public IP 100.31.186.21 in subnet-04fd2627f6fae2335, whose route table rtb-0d71f7a82c78aa5af has an active 0.0.0.0/0 route to igw-095e3728c39a3ae65, and acl-09263760a4356cb9b allows all ingress; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0. No instance profile is attached and the root volume vol-0a166969670754ca7 is encrypted.
- **Why it matters:** The host is directly attackable from the Internet without a load balancer or TLS-only front end; compromise is limited to this instance because it carries no IAM credentials.
- **Remediation:** Front the site with the existing ALB (or CloudFront) and remove the instance's public IP, or at minimum drop the plaintext tcp/80 rule from sg-055c437d6b40cde19 and keep only TLS from the load balancer's security group.

### 7. Metrics collector security group opens Prometheus port 9100 to the Internet (blocked only by a network ACL)
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** The instance has public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with an active 0.0.0.0/0 route to igw-095e3728c39a3ae65 (rtb-0d71f7a82c78aa5af), and sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0; only network ACL acl-0dae44201bff0235a rule 90 (deny tcp 9100 from 0.0.0.0/0, evaluated before allow-all rule 100) currently stops that traffic.
- **Why it matters:** A single network ACL edit would expose node-exporter metrics (host, process, and network telemetry) to the Internet; the instance has no IAM role, bounding further impact.
- **Remediation:** Change the sg-0e30fd4297eb362e8 port 9100 source to the scraper's security group or 10.80.0.0/16 (as done in sg-047a0edc57f953878), so the subnet ACL is not the only control.

### 8. Unencrypted root EBS volume on the reporting worker
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Root volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has encrypted = false and kms_key_id = null, while every other instance's root volume uses KMS key arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest and any snapshots of this volume lack KMS encryption, inconsistent with the rest of the fleet.
- **Remediation:** Snapshot the volume, create a KMS-encrypted copy, and replace the root volume (or relaunch the instance from an encrypted AMI) so encrypted = true with the account KMS key; enable EBS encryption by default in us-east-1.
