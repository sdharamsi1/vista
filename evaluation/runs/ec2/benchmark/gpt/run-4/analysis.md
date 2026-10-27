# EC2 Security Review

## Account Risk Summary
Eleven running EC2 instances were reviewed in `us-east-1`. The most serious risk is an Internet-accessible SSH host carrying account-wide administrator credentials; additional concerns include IAM privilege escalation, broadly scoped data access, and direct web-instance exposure.

## Top Findings

### 1. Internet-accessible SSH host has account-wide administrator credentials
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In `us-east-1`, the running instance has public IPv4 `184.195.174.188`, and route table `rtb-01318cc29d669c0eb` has an active `0.0.0.0/0` route to Internet gateway `igw-0a2ccf998af2d1439`. Security group `sg-0521ad17fec26a09a` permits TCP/22 from `0.0.0.0/0`, while its instance role has `AdministratorAccess`, allowing `"Action":"*"` on `"Resource":"*"`.
- **Why it matters:** Any successful access through the exposed SSH service would provide credentials capable of administrative control across the AWS account.
- **Remediation:** Remove the TCP/22 `0.0.0.0/0` rule and eliminate direct Internet SSH, using tightly controlled SSM access or an explicitly approved source range instead. Detach `AdministratorAccess` and replace it with only the specific permissions required, with no wildcard administrative access.

### 2. CI runner can grant itself or other roles arbitrary permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** In `us-east-1`, role `brightpath-ci-runner` allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on `"Resource":"*"`. The running instance can obtain this role through instance profile `arn:aws:iam::111122223333:instance-profile/brightpath-ci-runner`.
- **Why it matters:** Anyone obtaining the instance credentials could attach or create an administrative policy on a role, resulting in account-wide privilege escalation.
- **Remediation:** Remove `iam:AttachRolePolicy` and `iam:PutRolePolicy`; if deployment automation requires them, restrict resources to explicitly named deployment roles and constrain attachable policies with IAM conditions. The runner must not be able to modify its own role or attach arbitrary policies.

### 3. Internet-facing orders API combines IMDSv1 with access to every secret
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In `us-east-1`, active Internet-facing load balancer `arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/brightpath-storefront/edeb1e2578391384` forwards HTTPS requests matching `/api/*` to the healthy instance on TCP/8080. The instance has `http_tokens:"optional"`, and role `brightpath-orders-api` allows `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `"Resource":"*"`.
- **Why it matters:** If the reachable application exposes a server-side request or credential-access path, IMDSv1 can facilitate role credential theft, exposing secrets belonging to other workloads. Application behavior was not collected.
- **Remediation:** Set the instance metadata option `HttpTokens=required`. Replace the wildcard Secrets Manager resource with the exact secret ARN or ARNs required by the orders API.

### 4. Analytics notebook has unrestricted S3 permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** In `us-east-1`, role `brightpath-analytics-notebook` grants `s3:*` on `"Resource":"*"`. Security group `sg-037fdf8c5d0449baf` also permits TCP/8888 from the broad private range `10.0.0.0/8`.
- **Why it matters:** Credentials obtained from the notebook could read, alter, or delete S3 data across buckets accessible to the account, including data belonging to other workloads.
- **Remediation:** Replace `s3:*` and `"Resource":"*"` with required actions and exact bucket/object ARNs. Restrict TCP/8888 to a dedicated administrative security group or narrowly approved source range.

### 5. Marketing web instance is directly exposed to the Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** In `us-east-1`, the running instance has public IPv4 `100.31.186.21`, and route table `rtb-0d71f7a82c78aa5af` has an active `0.0.0.0/0` route to Internet gateway `igw-095e3728c39a3ae65`. Security group `sg-055c437d6b40cde19` permits TCP/80 and TCP/443 from `0.0.0.0/0`.
- **Why it matters:** Internet clients can connect directly to the instance on both plaintext HTTP and HTTPS, bypassing the isolation and centralized controls provided by a load balancer.
- **Remediation:** Remove the public IPv4 address and direct `0.0.0.0/0` instance ingress; place the service behind an Internet-facing load balancer and permit the application port only from the load balancer security group. Terminate HTTPS at the load balancer and redirect HTTP to HTTPS.

### 6. Image resizer accepts IMDSv1 requests
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** In `us-east-1`, the running instance has metadata `http_tokens:"optional"` and hop limit `2`. Its role can read and list `arn:aws:s3:::brightpath-media-uploads-111122223333` and `arn:aws:s3:::brightpath-media-uploads-111122223333/*`.
- **Why it matters:** A local or server-side request path capable of reaching metadata could obtain role credentials without an IMDSv2 token and expose media-bucket objects.
- **Remediation:** Set the instance metadata option `HttpTokens=required`. Reduce the metadata hop limit to `1` unless a demonstrated container or proxy architecture requires `2`.

### 7. Reporting worker root volume is unencrypted
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** In `us-east-1`, root volume `vol-0db09f8ba141ddec7` reports `encrypted:false` and `kms_key_id:null`. It is the attached `/dev/xvda` root device.
- **Why it matters:** Data stored on the volume lacks EBS encryption at rest, weakening protection if the volume or a derived snapshot becomes accessible.
- **Remediation:** Snapshot and copy or replace the volume using EBS encryption with an approved KMS key, then launch or migrate the instance to the encrypted root volume. Enable EBS encryption by default to prevent recurrence.
