# EC2 Security Review

## Account Risk Summary
Eleven running EC2 instances were reviewed in us-east-1. The most significant risks are an Internet-exposed administrator bastion and several instance roles capable of account-wide privilege escalation or broad cross-workload data access.

## Top Findings

### 1. Internet-exposed SSH bastion carries account administrator credentials
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1, the running instance has public IPv4 `184.195.174.188`, route table `rtb-01318cc29d669c0eb` routes `0.0.0.0/0` to Internet gateway `igw-0a2ccf998af2d1439`, and security group `sg-0521ad17fec26a09a` permits TCP/22 from `0.0.0.0/0`. Its role has managed policy `AdministratorAccess`, whose document allows action `*` on resource `*`.
- **Why it matters:** Compromise of the SSH-accessible host would expose credentials with administrative control over the AWS account.
- **Remediation:** Remove the TCP/22 `0.0.0.0/0` rule and eliminate the public IP, using the existing SSM capability or a tightly restricted access path instead. Detach `AdministratorAccess` and replace it with only the specific actions and resources required by the bastion.

### 2. CI runner can grant itself account-wide permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** In us-east-1, role `brightpath-ci-runner` allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `*`, with no conditions or permissions boundary. These permissions allow the role to modify IAM roles, including attaching or inserting more powerful policies.
- **Why it matters:** Code executing with this instance role can escalate from the current permissions to administrative access and then affect the entire account.
- **Remediation:** Remove `iam:AttachRolePolicy` and `iam:PutRolePolicy`; if IAM changes are essential, restrict them to designated role ARNs, approved policy ARNs, and mandatory permissions-boundary conditions. The runner must not be able to modify its own role or any role it can assume or pass.

### 3. Internet-facing orders API has access to every Secrets Manager secret
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In us-east-1, the active internet-facing load balancer `arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/brightpath-storefront/edeb1e2578391384` accepts HTTPS/443 from `0.0.0.0/0` and forwards `/api/*` to this healthy target on TCP/8080; the forwarding rule has no collected OIDC or Cognito authentication action. The instance role permits `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `*`, and metadata tokens are `optional`.
- **Why it matters:** If the public application or an SSRF path is exploited, its credentials could expose secrets belonging to unrelated workloads across the account.
- **Remediation:** Change the Secrets Manager statement from resource `*` to the exact secret ARN or ARNs required by the orders API. Set `instance_metadata.http_tokens` to `required`, and apply listener-level authentication where requests must be authenticated before reaching the application.

### 4. Analytics notebook role has unrestricted S3 control
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** In us-east-1, role `brightpath-analytics-notebook` allows `s3:*` on resource `*`. Security group `sg-037fdf8c5d0449baf` also permits TCP/8888 from the broad `10.0.0.0/8` source range.
- **Why it matters:** Compromise of the notebook could permit reading, modifying, or deleting S3 data across other workloads and buckets accessible to the account.
- **Remediation:** Replace `s3:*` on `*` with the minimum required S3 actions on explicit bucket and object ARNs. Restrict TCP/8888 to a dedicated administrative security group or specific trusted private CIDRs rather than `10.0.0.0/8`.

### 5. Marketing instance accepts unencrypted HTTP directly from the Internet
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0e6907bdc496a5f7a` (brightpath-marketing-site)
- **Evidence:** In us-east-1, the running instance has public IPv4 `100.31.186.21`, and route table `rtb-0d71f7a82c78aa5af` routes `0.0.0.0/0` to Internet gateway `igw-095e3728c39a3ae65`. Security group `sg-055c437d6b40cde19` permits TCP/80 and TCP/443 from `0.0.0.0/0`; unlike the collected ALB HTTP listener, no redirect is shown for this direct TCP/80 path.
- **Why it matters:** Clients using port 80 receive no transport-layer confidentiality or integrity, allowing an on-path party to observe or alter traffic.
- **Remediation:** Remove the TCP/80 ingress rule and expose only HTTPS/443, or place the instance behind a listener that performs an unconditional HTTP-to-HTTPS redirect. The end state should provide no direct plaintext application endpoint.

### 6. Image resizer permits IMDSv1 credential requests
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** In us-east-1, `instance_metadata.http_tokens` is `optional`, so IMDSv1 requests are accepted. The attached role can read objects from `arn:aws:s3:::brightpath-media-uploads-111122223333/*` and list `arn:aws:s3:::brightpath-media-uploads-111122223333`.
- **Why it matters:** A local request-forgery or host compromise could more easily retrieve role credentials and expose the media-upload bucket's contents.
- **Remediation:** Set `instance_metadata.http_tokens` to `required` and verify the applied state. Use a hop limit of `1` unless a documented container networking requirement needs a higher value.

### 7. Reporting worker root volume is unencrypted
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** In us-east-1, root volume `vol-0db09f8ba141ddec7` reports `encrypted: false` and `kms_key_id: null`; the other supplied instance root volumes are encrypted.
- **Why it matters:** Data on the reporting worker's root volume lacks the additional access control and cryptographic protection supplied by EBS encryption.
- **Remediation:** Snapshot and replace the root volume with an encrypted volume using an approved KMS key, verifying the replacement reports `encrypted: true`. Enforce EBS encryption by default for future volumes in us-east-1.
