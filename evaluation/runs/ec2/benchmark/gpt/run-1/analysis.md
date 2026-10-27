# EC2 Security Review

## Account Risk Summary
All 11 reviewed instances are running in `us-east-1`. The most significant risks are an Internet-reachable bastion carrying account-administrator credentials and multiple instance roles capable of privilege escalation or account-wide data access.

## Top Findings

### 1. Internet-reachable SSH bastion carries AdministratorAccess
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In `us-east-1`, the running instance has public IPv4 `184.195.174.188`, route table `rtb-01318cc29d669c0eb` has active `0.0.0.0/0` through Internet gateway `igw-0a2ccf998af2d1439`, and security group `sg-0521ad17fec26a09a` permits TCP/22 from `0.0.0.0/0`. Its role `brightpath-legacy-bastion` has `AdministratorAccess`, whose policy allows `"Action":"*"` on `"Resource":"*"`.
- **Why it matters:** SSH credentials or an exploitable SSH service are additional prerequisites, but compromise would expose administrator credentials capable of controlling the account.
- **Remediation:** Remove the TCP/22 `0.0.0.0/0` rule and eliminate the public IP, using SSM Session Manager or narrowly restricted administrative source CIDRs. Detach `AdministratorAccess` and replace it with only the specific permissions required for bastion management.

### 2. CI runner role can grant itself arbitrary IAM permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** In `us-east-1`, role `brightpath-ci-runner` allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on `"Resource":"*"`. These permissions allow the role to modify its own role or other roles with arbitrary inline or managed policies.
- **Why it matters:** An actor obtaining the instance-role credentials could grant the role administrative permissions, resulting in account-wide control.
- **Remediation:** Remove `iam:AttachRolePolicy` and `iam:PutRolePolicy` from the instance role. If policy deployment is required, move it to a separate controlled deployment role and restrict target role ARNs, permitted policy ARNs, and policy contents with conditions and a permissions boundary.

### 3. Orders API role can read every Secrets Manager secret
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In `us-east-1`, role `brightpath-orders-api` allows `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `"Resource":"*"`. The instance also has metadata `http_tokens:"optional"` and `hop_limit:2`, permitting IMDSv1 credential requests.
- **Why it matters:** Compromise of the instance or theft of its role credentials could disclose Secrets Manager data belonging to unrelated workloads across the account.
- **Remediation:** Replace `"Resource":"*"` with the exact secret ARNs required by the orders service. Set instance metadata `http_tokens` to `required` and retain the metadata endpoint only if the workload needs it.

### 4. Analytics notebook role has unrestricted S3 control
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** In `us-east-1`, role `brightpath-analytics-notebook` has an inline statement allowing `s3:*` on `"Resource":"*"`. This includes read, modification, and deletion operations across S3 resources accessible in the account.
- **Why it matters:** Compromise of the notebook or its role credentials could expose or alter data belonging to multiple workloads.
- **Remediation:** Replace `s3:*` and `"Resource":"*"` with the minimum required actions and exact bucket and object ARNs. Separate read and write permissions and omit deletion, bucket-policy, and access-control actions unless explicitly required.

### 5. Orders API is forwarded from the Internet without load-balancer authentication
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In `us-east-1`, active Internet-facing load balancer `arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/brightpath-storefront/edeb1e2578391384` accepts HTTPS/443 from `0.0.0.0/0` and forwards `/api/*` to the healthy instance on TCP/8080. The forwarding relationship has `authentication_actions:[]`; authentication inside the application was not collected.
- **Why it matters:** Internet clients can reach the orders API directly through the ALB. Unauthorized API access depends on whether the application independently enforces authentication and authorization.
- **Remediation:** Add an `authenticate-oidc` or `authenticate-cognito` action before the `/api/*` forward action, or restrict the listener rule to required source networks. The end state should require verified identity before requests reach the target.

### 6. Reporting worker root volume is unencrypted
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** In `us-east-1`, root volume `vol-0db09f8ba141ddec7` reports `encrypted:false` and `kms_key_id:null`; every other supplied root volume reports encryption enabled.
- **Why it matters:** Data on the volume and derived snapshots lack EBS encryption-at-rest protection, increasing exposure if storage-level access is obtained.
- **Remediation:** Create an encrypted replacement volume from an encrypted snapshot using an appropriate KMS key, migrate the root device, and ensure future launches set EBS encryption to enabled.

### 7. Image resizer permits IMDSv1 credential requests
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** In `us-east-1`, instance metadata is enabled with `http_tokens:"optional"` and `hop_limit:2`. Its role can read bucket `arn:aws:s3:::brightpath-media-uploads-111122223333` and its objects through `s3:ListBucket` and `s3:GetObject`.
- **Why it matters:** A suitable SSRF or local-access condition could retrieve role credentials through tokenless IMDSv1 and expose uploaded media objects.
- **Remediation:** Set metadata `http_tokens` to `required`; reduce `hop_limit` to `1` unless container networking demonstrably requires a higher value. The end state should accept only token-authenticated IMDSv2 requests.

### 8. Marketing site permits direct plaintext HTTP
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** In `us-east-1`, the running instance has public IPv4 `100.31.186.21`, route table `rtb-0d71f7a82c78aa5af` routes `0.0.0.0/0` to Internet gateway `igw-095e3728c39a3ae65`, and security group `sg-055c437d6b40cde19` permits TCP/80 and TCP/443 from `0.0.0.0/0`. No load-balancer relationship or application-level HTTP redirect behavior was collected.
- **Why it matters:** Clients using port 80 may transmit requests without transport encryption unless the application immediately redirects them.
- **Remediation:** Remove the TCP/80 ingress rule if HTTP is unnecessary, or place the instance behind a listener that returns an unconditional HTTP-to-HTTPS redirect. The end state should serve application content only over HTTPS.
