# EC2 Security Review

## Account Risk Summary
All 11 running instances are in us-east-1 across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). The dominant risks are an Internet-facing bastion with world-open SSH attached to an AdministratorAccess role, plus several instance roles with wildcard IAM/S3/Secrets Manager permissions and two instances still accepting IMDSv1.

## Top Findings

### 1. Internet-open SSH on a bastion holding AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1, the instance is running with public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has an active 0.0.0.0/0 route to igw-0a2ccf998af2d1439, and NACL acl-0b53e66e7bfebf35d allows all ingress; sg-0521ad17fec26a09a allows tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration"). Its instance profile brightpath-legacy-bastion attaches the managed policy AdministratorAccess (Allow `*` on `*`), last used 2026-10-21T00:18:09Z.
- **Why it matters:** Any Internet host can reach the SSH service, and a successful login or application compromise yields instance-profile credentials with full administrative control of account 111122223333.
- **Remediation:** Remove the tcp/22 0.0.0.0/0 rule from sg-0521ad17fec26a09a (restrict to a corporate CIDR or use SSM Session Manager) and replace AdministratorAccess on role brightpath-legacy-bastion with a least-privilege policy scoped to the tasks the host performs.

### 2. CI runner role can attach or inline any IAM policy (privilege escalation)
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** Instance profile brightpath-ci-runner carries inline policy "permissions" allowing `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `*` (role last used 2026-10-21T00:19:50Z). The instance is in private subnet-0c15f9cb55de4e1b6 (route table rtb-021f485c86ae5e308 egresses via nat-0655e4de3667d0e70) with sg-01ee4d1d0c69cd2e9 having no ingress rules.
- **Why it matters:** Anyone who obtains these credentials can attach AdministratorAccess to any role in the account, converting limited access into account-wide administrative control.
- **Remediation:** Scope the inline policy's `iam:AttachRolePolicy`/`iam:PutRolePolicy` to specific role ARNs with an `iam:PermissionsBoundary` condition, or remove the IAM write permissions from role brightpath-ci-runner entirely.

### 3. Analytics notebook role grants s3:* on all buckets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Instance profile brightpath-analytics-notebook includes inline policy "data-access" allowing `s3:*` on `*`. The instance listens on tcp/8888 ("Jupyter") per sg-037fdf8c5d0449baf with source 10.0.0.0/8, which covers the whole VPC range 10.80.0.0/16.
- **Why it matters:** Credentials from this host allow read, write and delete of every S3 bucket in the account, including data belonging to other workloads such as brightpath-media-uploads-111122223333.
- **Remediation:** Replace `s3:*` on `*` with the specific bucket ARNs and actions the notebook needs, and narrow the 8888 ingress rule in sg-037fdf8c5d0449baf to the specific client security group or CIDR.

### 4. Orders API role can read every Secrets Manager secret
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** Instance profile brightpath-orders-api has inline policy "permissions" allowing `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `*` (role last used 2026-10-21T00:24:26Z). The instance is reachable from the Internet through internet-facing ALB brightpath-storefront (state active, sg-0f2ef87dec0737621 allows 443 and 80 from 0.0.0.0/0) via listener rule priority 10 path `/api/*` to target group brightpath-orders-api on port 8080.
- **Why it matters:** An application-level compromise of this Internet-reachable service exposes all secrets in the account, not just the order service's own credentials.
- **Remediation:** Restrict the Secrets Manager statement to the exact secret ARNs the orders API requires so the role cannot read other workloads' secrets.

### 5. IMDSv1 still accepted on two instances
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api), `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** Both us-east-1 instances have instance_metadata.http_tokens = "optional" with endpoint enabled and hop_limit 2, so unauthenticated IMDSv1 requests succeed; the remaining nine instances are set to "required". Attached roles are brightpath-orders-api (secretsmanager read on `*`, dynamodb table/orders) and brightpath-image-resizer (s3:GetObject/ListBucket on brightpath-media-uploads-111122223333).
- **Why it matters:** IMDSv1 lets a server-side request forgery or proxy flaw in the hosted application retrieve role credentials with a single unauthenticated GET.
- **Remediation:** Set metadata options to http_tokens=required (IMDSv2 only) on both instances and keep hop_limit at 1 where no container network hop is needed.

### 6. Marketing site instance exposed directly to the Internet on 80/443
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** Running in us-east-1 with public IP 100.31.186.21 in subnet-04fd2627f6fae2335, route table rtb-0d71f7a82c78aa5af has an active 0.0.0.0/0 route to igw-095e3728c39a3ae65 and NACL acl-09263760a4356cb9b allows all ingress; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0. No instance profile is attached and the root volume vol-0a166969670754ca7 is encrypted.
- **Why it matters:** The web service is directly attackable from the Internet without passing through the ALB's TLS termination, and plaintext tcp/80 is accepted; blast radius is limited because the instance holds no IAM credentials.
- **Remediation:** Front this workload with the existing ALB (or at minimum drop tcp/80 and keep only 443) so sg-055c437d6b40cde19 accepts traffic from sg-0f2ef87dec0737621 rather than 0.0.0.0/0.

### 7. Metrics collector security group opens node-exporter 9100 to the Internet
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** The instance has public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with an IGW route via rtb-0d71f7a82c78aa5af, and sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0; only NACL acl-0dae44201bff0235a rule 90 (deny tcp 9100 from 0.0.0.0/0, evaluated before allow rule 100) currently blocks that traffic.
- **Why it matters:** Internet exposure of host metrics depends on a single NACL deny rule; removing or renumbering it immediately exposes the metrics endpoint and host inventory data.
- **Remediation:** Change the sg-0e30fd4297eb362e8 ingress rule for 9100 to source 10.80.0.0/16 (or the Prometheus security group) so exposure is not dependent on the NACL entry.

### 8. Unencrypted root EBS volume
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Root volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has encrypted=false and kms_key_id=null, while every other instance's root volume is encrypted with KMS key arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest and any snapshots of this volume are stored without KMS encryption, inconsistent with the rest of the fleet.
- **Remediation:** Recreate the instance from an encrypted snapshot (or enable EBS encryption by default in us-east-1) so the root volume uses the existing KMS key.
