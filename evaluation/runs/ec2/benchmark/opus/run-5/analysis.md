# EC2 Security Review

## Account Risk Summary
All 11 running instances live in a single region (us-east-1) across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). The dominant risks are an Internet-exposed SSH bastion carrying AdministratorAccess, several over-broad instance roles (`s3:*`, `iam:PutRolePolicy`, `secretsmanager:GetSecretValue` on `*`), and two instances still accepting IMDSv1.

## Top Findings

### 1. Internet-wide SSH on a bastion whose instance role has AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** Running instance has public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has an active 0.0.0.0/0 route to igw-0a2ccf998af2d1439; sg-0521ad17fec26a09a allows tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration") and NACL acl-0b53e66e7bfebf35d allows all ingress. Its instance profile brightpath-legacy-bastion attaches the managed policy AdministratorAccess (`"*"` on `"*"`), last used 2026-10-21T00:18:09Z (us-east-1).
- **Why it matters:** Any Internet host can reach the SSH service, and any code execution or metadata access on this host yields full administrative control of account 111122223333.
- **Remediation:** Remove the 0.0.0.0/0 tcp/22 ingress rule from sg-0521ad17fec26a09a (restrict to known CIDRs or replace with SSM Session Manager) and replace AdministratorAccess on role brightpath-legacy-bastion with a least-privilege policy.

### 2. Internet-reachable orders API role can read every secret in the account
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** Inline policy "permissions" on role brightpath-orders-api allows `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `"*"`. The instance is a healthy target on port 8080 of the internet-facing ALB brightpath-storefront (listener HTTPS:443, rule priority 10, path `/api/*`), whose SG sg-0f2ef87dec0737621 accepts 0.0.0.0/0 on 80/443; the instance also has `http_tokens: optional`.
- **Why it matters:** Application-level compromise or SSRF on this Internet-served instance exposes all Secrets Manager secrets in the account, not just the orders workload's own credentials.
- **Remediation:** Scope the Secrets Manager statement to the specific secret ARNs the service needs and set the instance's metadata options to `http_tokens: required`.

### 3. CI runner role can attach or inline any IAM policy (privilege escalation to admin)
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** Inline policy "permissions" on role brightpath-ci-runner allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `"*"`; the role was last used 2026-10-21T00:19:50Z in us-east-1. The instance is in private subnet-0c15f9cb55de4e1b6 (route table rtb-021f485c86ae5e308 egresses via nat-0655e4de3667d0e70) with no ingress rules in sg-01ee4d1d0c69cd2e9.
- **Why it matters:** Any access to this instance's credentials allows attaching AdministratorAccess to its own or any other role, converting bounded access into account-wide administrative control.
- **Remediation:** Remove the wildcard `iam:AttachRolePolicy`/`iam:PutRolePolicy` grant, or restrict it to specific role ARNs with an `iam:PermissionsBoundary` condition.

### 4. Analytics notebook role grants s3:* on all buckets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Inline policy "data-access" on role brightpath-analytics-notebook allows `s3:*` on `"*"` (role last used 2026-10-21T00:20:47Z). The instance sits in private subnet-0c15f9cb55de4e1b6 with sg-037fdf8c5d0449baf allowing tcp/8888 ("Jupyter") from the entire 10.0.0.0/8 range.
- **Why it matters:** Anyone who reaches the Jupyter port from any 10.0.0.0/8 source, or otherwise executes code on the host, gains read/write/delete over every S3 bucket in the account, including other workloads' data.
- **Remediation:** Replace `s3:*` on `*` with the specific bucket ARNs and actions required, and narrow the tcp/8888 source in sg-037fdf8c5d0449baf to the specific client subnet or security group.

### 5. IMDSv1 still accepted on two instances with IAM roles
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api), `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** Both instances report `instance_metadata.http_tokens: optional` with endpoint enabled and hop_limit 2 (us-east-1); both have instance profiles (brightpath-orders-api, brightpath-image-resizer), so role credentials are retrievable from IMDS without a session token.
- **Why it matters:** Token-less IMDS requests let a server-side request forgery or proxy flaw in the hosted application retrieve the instance role's temporary credentials.
- **Remediation:** Set metadata options to `http_tokens: required` (IMDSv2 only) on both instances, keeping hop limit at 1 unless containers require 2.

### 6. Marketing site instance exposed directly to the Internet on HTTP and HTTPS
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** Running instance has public IP 100.31.186.21 in subnet-04fd2627f6fae2335, whose route table rtb-0d71f7a82c78aa5af has an active 0.0.0.0/0 route to igw-095e3728c39a3ae65; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0 and acl-09263760a4356cb9b allows all ingress. The instance has no instance profile.
- **Why it matters:** The host is directly reachable from the Internet, including in plaintext on port 80, without passing through the ALB that terminates TLS for other workloads; compromise is limited to this instance since it carries no IAM role.
- **Remediation:** Serve this site behind the existing ALB (or at minimum drop the 0.0.0.0/0 tcp/80 rule and remove the public IP), leaving no direct Internet-facing listener on the instance.

### 7. Node-exporter port 9100 open to 0.0.0.0/0 on a public instance, blocked only by a network ACL rule
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** Instance has public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with an IGW route (rtb-0d71f7a82c78aa5af → igw-095e3728c39a3ae65), and sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0; NACL acl-0dae44201bff0235a rule 90 denies ingress tcp/9100 from 0.0.0.0/0 ahead of its allow-all rule 100, so the traffic is currently dropped at the subnet boundary.
- **Why it matters:** The only control preventing Internet access to the metrics endpoint is a single NACL rule; removing or reordering it would immediately expose host telemetry on this instance (which carries no IAM role).
- **Remediation:** Restrict the tcp/9100 ingress rule in sg-0e30fd4297eb362e8 to the Prometheus scraper's security group or 10.80.0.0/16 so exposure does not depend on NACL rule 90.

### 8. Unencrypted root EBS volume
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Root volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has `encrypted: false` and no `kms_key_id`, while every other instance's root volume is encrypted with arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest on this volume and any snapshots taken from it lack KMS encryption, unlike the rest of the fleet.
- **Remediation:** Re-create the volume from an encrypted snapshot using the existing KMS key (or relaunch the instance from an encrypted AMI) and enable EBS encryption by default in us-east-1.
