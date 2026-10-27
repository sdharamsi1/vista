# EC2 Security Review

## Account Risk Summary
All 11 running instances live in us-east-1 across two VPCs (vpc-03009df4f26c47700 and vpc-0b50213f9be36f02c). The dominant risks are an Internet-reachable SSH bastion carrying an AdministratorAccess role, several instance roles with wildcard or privilege-escalating permissions, and two instances still accepting IMDSv1.

## Top Findings

### 1. Internet-open SSH on a bastion whose instance role has AdministratorAccess
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1 the instance is running with public IP 184.195.174.188 in subnet-023990080e209f3d4, whose route table rtb-01318cc29d669c0eb has 0.0.0.0/0 → igw-0a2ccf998af2d1439; sg-0521ad17fec26a09a allows tcp/22 from 0.0.0.0/0 ("SSH - temporary for migration") and NACL acl-0b53e66e7bfebf35d allows all ingress. Its instance profile brightpath-legacy-bastion attaches arn:aws:iam::aws:policy/AdministratorAccess (Allow `*` on `*`), last used 2026-10-21T00:18:09Z.
- **Why it matters:** Any host on the Internet can reach the SSH service, and a successful login or any remote code execution yields metadata-service credentials with full administrative control of account 111122223333.
- **Remediation:** Restrict sg-0521ad17fec26a09a tcp/22 to specific trusted CIDRs (or remove it and use SSM Session Manager, as other instances do) and replace AdministratorAccess on role brightpath-legacy-bastion with a least-privilege policy.

### 2. CI runner role can escalate to any permission via iam:PutRolePolicy/AttachRolePolicy on all roles
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** Instance profile brightpath-ci-runner's inline policy "permissions" allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `*` (role last used 2026-10-21T00:19:50Z). The instance is in private subnet-0c15f9cb55de4e1b6 (rtb-021f485c86ae5e308 → nat-0655e4de3667d0e70) with sg-01ee4d1d0c69cd2e9 having no ingress rules.
- **Why it matters:** Anyone who obtains these instance credentials can attach AdministratorAccess to any role in the account, converting a single workload compromise into account-wide administrative control.
- **Remediation:** Scope the inline policy to the specific roles the CI workflow manages and add a permissions boundary condition, so no statement grants iam:PutRolePolicy/AttachRolePolicy on `*`.

### 3. Internet-facing ALB target holds account-wide Secrets Manager read
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** Role brightpath-orders-api inline policy allows `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on resource `*`. The instance is a healthy target on port 8080 of the active internet-facing ALB brightpath-storefront (HTTPS:443 listener, rule priority 10, path `/api/*`), and its metadata service accepts IMDSv1 (`http_tokens: optional`, hop_limit 2).
- **Why it matters:** An application flaw or SSRF in the Internet-reachable API can retrieve every secret in account 111122223333, not just those this service needs.
- **Remediation:** Restrict the secretsmanager statement to the specific secret ARNs the orders API uses, and set the instance metadata options to `http_tokens: required`.

### 4. Analytics notebook role grants s3:* on all buckets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** Instance profile brightpath-analytics-notebook inline policy "data-access" allows `s3:*` on `*` (role last used 2026-10-21T00:20:47Z). The instance sits in private subnet-0c15f9cb55de4e1b6 with sg-037fdf8c5d0449baf allowing tcp/8888 ("Jupyter") from 10.0.0.0/8, which spans far more than the VPC CIDR 10.80.0.0/16.
- **Why it matters:** Credentials from this instance permit read, write and delete on every S3 bucket in the account, including data belonging to other workloads such as brightpath-media-uploads-111122223333.
- **Remediation:** Replace `s3:*` on `*` with explicit actions on the specific bucket ARNs the notebook needs, and narrow the port 8888 source from 10.0.0.0/8 to the specific client CIDR or security group.

### 5. IMDSv1 accepted on instances with IAM credentials
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer), `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** Both us-east-1 instances report `instance_metadata.http_tokens: optional` with `hop_limit: 2`, while all other nine instances use `required`. Both carry instance profiles (brightpath-image-resizer with s3:GetObject/ListBucket on brightpath-media-uploads-111122223333; brightpath-orders-api with DynamoDB table/orders and Secrets Manager access).
- **Why it matters:** IMDSv1 lets a server-side request forgery or proxy bug fetch role credentials with a simple unauthenticated GET, with no session-token requirement to block it.
- **Remediation:** Set metadata options to `http_tokens: required` (and hop limit 1 where no container networking is needed) on both instances.

### 6. Marketing site instance directly exposed to the Internet on HTTP/HTTPS
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** Running in us-east-1 with public IP 100.31.186.21 in subnet-04fd2627f6fae2335, whose route table rtb-0d71f7a82c78aa5af has 0.0.0.0/0 → igw-095e3728c39a3ae65; sg-055c437d6b40cde19 allows tcp/80 and tcp/443 from 0.0.0.0/0 and NACL acl-09263760a4356cb9b allows all ingress. The instance has no instance profile (`instance_profile_arn: null`).
- **Why it matters:** The instance's own web stack, including plaintext port 80, is reachable from any Internet host without the ALB termination and TLS policy used by the storefront; compromise is limited to this instance because it carries no IAM credentials.
- **Remediation:** Place this workload behind the brightpath-storefront ALB (or an equivalent HTTPS listener) and remove the public IP, or at minimum drop the 0.0.0.0/0 tcp/80 rule and serve only HTTPS.

### 7. Node-exporter port 9100 open to 0.0.0.0/0 on an Internet-addressable instance
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0ffe8aad2d1cdfe53` (brightpath-metrics-collector)
- **Evidence:** The instance has public IP 44.213.120.155 in subnet-03845fb144ad9fc67 with route 0.0.0.0/0 → igw-095e3728c39a3ae65 (rtb-0d71f7a82c78aa5af), and sg-0e30fd4297eb362e8 allows tcp/9100 from 0.0.0.0/0; NACL acl-0dae44201bff0235a rule 90 currently denies ingress tcp/9100 from 0.0.0.0/0, blocking the path.
- **Why it matters:** Internet reachability of host metrics depends solely on one NACL deny rule; removing or reordering it would immediately expose metrics endpoint data on this instance.
- **Remediation:** Change the sg-0e30fd4297eb362e8 tcp/9100 source from 0.0.0.0/0 to the Prometheus scraper's security group or 10.80.0.0/16, matching sg-047a0edc57f953878.

### 8. Unencrypted root EBS volume
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** Root volume vol-0db09f8ba141ddec7 (/dev/xvda, gp3, 8 GiB) has `encrypted: false` and `kms_key_id: null`, while every other instance's root volume is encrypted with arn:aws:kms:us-east-1:111122223333:key/65a55065-9308-4485-ba5d-c1b854c677f9.
- **Why it matters:** Data at rest on this volume and any snapshot taken from it is stored without KMS encryption, inconsistent with the rest of the fleet.
- **Remediation:** Recreate the instance from an encrypted snapshot (or copy-with-encryption using the existing KMS key) and enable EBS encryption by default in us-east-1, so all attached volumes report `encrypted: true`.
