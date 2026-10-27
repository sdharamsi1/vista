# EC2 Security Review

## Account Risk Summary
All 11 running instances live in us-east-1 across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). The dominant risks are a world-open SSH bastion carrying an AdministratorAccess role, and several instance roles with wildcard-resource IAM permissions, two of them on instances still accepting IMDSv1.

## Top Findings

### 1. Internet-wide SSH to a bastion whose instance role has AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** Running instance has public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has an active 0.0.0.0/0 route to igw-0a2ccf998af2d1439, and NACL acl-0b53e66e7bfebf35d allows all ingress; sg-0521ad17fec26a09a permits tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration"). Its instance profile brightpath-legacy-bastion attaches the managed policy AdministratorAccess (Allow `*` on `*`), last used 2026-10-21T00:18:09Z.
- **Why it matters:** Any Internet host can reach the SSH service, and any code execution or credential retrieval from IMDS on this host yields full administrative control of account 111122223333.
- **Remediation:** Replace the 0.0.0.0/0 tcp/22 rule in sg-0521ad17fec26a09a with specific admin CIDRs (or remove SSH ingress and use SSM Session Manager), and detach AdministratorAccess from role brightpath-legacy-bastion in favor of a least-privilege policy scoped to the resources the bastion needs.

### 2. Internet-reachable orders API allows IMDSv1 and its role can read every secret in the account
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** instance_metadata.http_tokens is `optional` (hop_limit 2); the instance is a healthy target on port 8080 of target group brightpath-orders-api, reached from the internet-facing ALB brightpath-storefront (state active, sg-0f2ef87dec0737621 allows 443 and 80 from 0.0.0.0/0) via listener rule priority 10 for path `/api/*`. Its role brightpath-orders-api has an inline statement allowing `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `"*"`.
- **Why it matters:** A request-forgery or code-execution flaw in the Internet-exposed application can fetch role credentials over IMDSv1 without a token and then read every Secrets Manager secret in the account.
- **Remediation:** Set http_tokens to `required` on this instance and scope the Secrets Manager statement to the specific secret ARNs the API needs.

### 3. Instance roles grant account-wide wildcard permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner), `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Role brightpath-ci-runner has inline policy "permissions" allowing `iam:AttachRolePolicy` and `iam:PutRolePolicy` on `"*"`; role brightpath-analytics-notebook has inline policy "data-access" allowing `s3:*` on `"*"`. Both roles were used recently (2026-10-21T00:19:50Z and 00:20:47Z) and both instances run in private subnet-0c15f9cb55de4e1b6 (rtb-021f485c86ae5e308 egresses via nat-0655e4de3667d0e70).
- **Why it matters:** Credentials from either host allow privilege escalation to administrator (attaching AdministratorAccess to any role) or read/write/delete of all S3 data in the account, far beyond the owning workload.
- **Remediation:** Remove the `iam:AttachRolePolicy`/`iam:PutRolePolicy` grant (or restrict it to specific role ARNs with a permissions boundary condition) and replace `s3:*` on `*` with explicit actions on the specific bucket ARNs the notebook needs.

### 4. IMDSv1 accepted on image-resizer instance
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** instance_metadata.http_tokens is `optional` with hop_limit 2; the attached role brightpath-image-resizer allows `s3:GetObject` and `s3:ListBucket` on arn:aws:s3:::brightpath-media-uploads-111122223333 and its objects. The instance is in private subnet-0c15f9cb55de4e1b6 with no ingress rules in sg-00e85873169a4dd0b.
- **Why it matters:** Token-less IMDS access lets any server-side request forgery or local code execution retrieve role credentials and read the media-uploads bucket.
- **Remediation:** Set http_tokens to `required` (IMDSv2 only) on this instance; end state is no instance in the account with http_tokens `optional`.

### 5. Marketing site instance directly exposed to the Internet on HTTP and HTTPS
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** Public IP 100.31.186.21 in subnet-04fd2627f6fae2335, whose route table rtb-0d71f7a82c78aa5af has an active 0.0.0.0/0 route to igw-095e3728c39a3ae65; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0 and acl-09263760a4356cb9b allows all ingress. The instance has no instance profile (iam.instance_profile_arn is null) and http_tokens is `required`.
- **Why it matters:** The web service is directly reachable by any Internet host with no load balancer or TLS termination in front of port 80, so application flaws are exposed and plaintext HTTP traffic is accepted; blast radius is limited to this host since it holds no IAM credentials.
- **Remediation:** Place the site behind the existing ALB (or restrict sg-055c437d6b40cde19 to the ALB security group) and redirect port 80 to HTTPS, leaving no direct 0.0.0.0/0 instance-level listener.

### 6. Security group opens Prometheus node-exporter port 9100 to the Internet on a public instance
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** Public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with an active 0.0.0.0/0 route to igw-095e3728c39a3ae65 (rtb-0d71f7a82c78aa5af), and sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0; however NACL acl-0dae44201bff0235a rule 90 denies ingress tcp/9100 from 0.0.0.0/0 ahead of the allow-all rule 100, so the traffic is currently blocked at the subnet boundary.
- **Why it matters:** Exposure depends solely on one NACL rule; removing or reordering acl-0dae44201bff0235a rule 90 would immediately publish host metrics endpoints to the Internet.
- **Remediation:** Restrict the sg-0e30fd4297eb362e8 tcp/9100 rule to the Prometheus scraper source (e.g. 10.80.0.0/16 or the scraper's security group) instead of relying on the NACL deny.

### 7. Root EBS volume unencrypted on reporting worker
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has encrypted=false and kms_key_id=null, while every other instance's root volume is encrypted with arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest and any snapshots of this volume lack KMS protection, inconsistent with the rest of the fleet.
- **Remediation:** Re-create the instance from an encrypted snapshot (or replace the root volume) so vol-0db09f8ba141ddec7's successor is encrypted with the account KMS key, and enable EBS encryption-by-default in us-east-1.
