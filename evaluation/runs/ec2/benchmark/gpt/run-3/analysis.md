# EC2 Security Review

## Account Risk Summary
Eleven running EC2 instances were reviewed in us-east-1. Overall risk is elevated by an Internet-exposed administrative instance and several instance roles capable of account-wide privilege escalation or broad access to other workloads.

## Top Findings

### 1. Internet-exposed SSH host carries account administrator credentials
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1, public IPv4 `184.195.174.188` has an active `0.0.0.0/0` route through Internet gateway `igw-0a2ccf998af2d1439`; security group `sg-0521ad17fec26a09a` permits TCP/22 from `0.0.0.0/0`, and the network ACL permits all ingress. Its role has managed policy `arn:aws:iam::aws:policy/AdministratorAccess`, whose policy allows action `*` on resource `*`; SSH authentication and runtime software were not collected.
- **Why it matters:** Compromise of the SSH service or credentials would expose administrator-level AWS credentials, enabling account-wide control.
- **Remediation:** Remove the TCP/22 `0.0.0.0/0` rule and public IPv4 path; use SSM Session Manager or restrict SSH to explicit trusted source CIDRs. Detach `AdministratorAccess` and replace it with permissions limited to the bastion’s required resources and actions.

### 2. CI runner can grant itself or other roles arbitrary permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** In us-east-1, role `arn:aws:iam::111122223333:role/brightpath-ci-runner` allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `*`, with no permissions boundary. The running instance can obtain this role’s credentials through its attached instance profile.
- **Why it matters:** Anyone controlling the instance or its role credentials could attach or create an administrative policy on a role, including the runner’s own role, and gain account-wide control.
- **Remediation:** Remove `iam:AttachRolePolicy` and `iam:PutRolePolicy` from the instance role. If policy management is required, place it in a separate deployment role, restrict it to named non-privileged role ARNs and approved policy ARNs, and apply a permissions boundary that prevents privilege escalation.

### 3. Public orders API combines broad secret access with IMDSv1
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In us-east-1, active Internet-facing load balancer `arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/brightpath-storefront/edeb1e2578391384` accepts HTTPS/443 from `0.0.0.0/0` and forwards `/api/*` without an OIDC or Cognito action to the healthy instance on TCP/8080. The instance has `http_tokens: optional`, and its role permits `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `*`, plus read/write operations on `arn:aws:dynamodb:us-east-1:111122223333:table/orders`; application-level authentication was not collected.
- **Why it matters:** An application compromise or metadata-access flaw could expose every Secrets Manager secret permitted by IAM and allow modification of the orders table.
- **Remediation:** Set instance metadata `http_tokens` to `required`. Replace the Secrets Manager resource `*` with the exact required secret ARNs, and configure ALB OIDC/Cognito authentication or restrict listener sources wherever the API is not intended to be anonymous.

### 4. Analytics notebook role has unrestricted S3 control
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** In us-east-1, role `arn:aws:iam::111122223333:role/brightpath-analytics-notebook` contains an inline statement allowing `s3:*` on resource `*`, with no permissions boundary. Security group `sg-037fdf8c5d0449baf` also permits TCP/8888 from the broad `10.0.0.0/8` range.
- **Why it matters:** Compromise of the notebook or its role credentials could read, modify, delete, or reconfigure S3 data belonging to other workloads in the account.
- **Remediation:** Replace `s3:*` on `*` with only the required object and bucket actions on explicit bucket and object ARNs. Restrict TCP/8888 to a dedicated trusted security group or narrowly defined administration CIDRs.

### 5. Marketing host is directly reachable from the Internet
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** In us-east-1, public IPv4 `100.31.186.21` uses route table `rtb-0d71f7a82c78aa5af`, which has an active `0.0.0.0/0` route to Internet gateway `igw-095e3728c39a3ae65`. Security group `sg-055c437d6b40cde19` permits TCP/80 and TCP/443 from `0.0.0.0/0`, while network ACL `acl-09263760a4356cb9b` permits all ingress; runtime service behavior was not collected.
- **Why it matters:** Internet clients can connect directly to the instance’s web ports, increasing the attack surface and placing any resulting compromise directly on the host.
- **Remediation:** Place the service behind an Internet-facing ALB, remove the instance’s public IPv4 address, and allow the application port only from the ALB security group. Remove TCP/80 if unnecessary, or limit it to an HTTPS redirecting edge listener.

### 6. Image resizer permits IMDSv1 access to scoped S3 credentials
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** In us-east-1, instance metadata is enabled with `http_tokens: optional`, so IMDSv1 requests are accepted. The attached role can run `s3:GetObject` and `s3:ListBucket` against `arn:aws:s3:::brightpath-media-uploads-111122223333` and its objects.
- **Why it matters:** If an attacker first obtains local request capability, such as through an SSRF condition, IMDSv1 makes theft of credentials able to read the media bucket easier.
- **Remediation:** Set instance metadata `http_tokens` to `required` and retain the existing bucket-scoped permissions or narrow them further to required object prefixes.

### 7. Reporting worker root volume is unencrypted
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** In us-east-1, root volume `vol-0db09f8ba141ddec7` reports `encrypted: false` and `kms_key_id: null`; the other supplied root volumes are encrypted.
- **Why it matters:** Data on the root volume and derived snapshots lacks EBS encryption-at-rest protection, increasing exposure if storage-level access is obtained.
- **Remediation:** Create an encrypted replacement from an encrypted snapshot using an approved KMS key, attach it as the root volume, and enable EBS encryption by default so future volumes and snapshots are encrypted.
