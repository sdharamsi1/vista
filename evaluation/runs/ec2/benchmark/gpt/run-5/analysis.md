# EC2 Security Review

## Account Risk Summary
Eleven running EC2 instances were reviewed in us-east-1. The most significant risks are an Internet-wide SSH path to an administrator-privileged instance, a public API carrying broad secret access, and two private instances with account-impacting IAM permissions.

## Top Findings

### 1. Internet-wide SSH exposure on an administrator-privileged instance
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-05eab7e76d1a7e0e6` (brightpath-legacy-bastion)
- **Evidence:** In us-east-1, the running instance has public IPv4 `184.195.174.188`; route table `rtb-01318cc29d669c0eb` has an active `0.0.0.0/0` route to Internet gateway `igw-0a2ccf998af2d1439`, and security group `sg-0521ad17fec26a09a` allows TCP/22 from `0.0.0.0/0`. Its role has `AdministratorAccess`, whose policy allows action `"*"` on resource `"*"`.
- **Why it matters:** Exploiting SSH or obtaining valid host access would expose administrator credentials capable of controlling the account. SSH service and authentication details were not collected.
- **Remediation:** Remove the `0.0.0.0/0` TCP/22 rule and eliminate the public SSH path, preferably using SSM Session Manager; otherwise restrict it to specific trusted source CIDRs. Detach `AdministratorAccess` and replace it with only the permissions required by this instance.

### 2. Public orders API combines external attack surface with broad secret access
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** PARTIAL
- **Category:** INTERNET_EXPOSURE
- **Affected instances:** `i-0fac06eba5d0109a7` (brightpath-orders-api)
- **Evidence:** In us-east-1, active internet-facing load balancer `arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/brightpath-storefront/edeb1e2578391384` accepts HTTPS/443 from `0.0.0.0/0` and forwards `/api/*` to the healthy instance on TCP/8080; `authentication_actions` is empty. The instance role permits `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on `"*"`, while metadata tokens are `optional` with hop limit `2`.
- **Why it matters:** An application-level weakness could lead to access to every Secrets Manager secret authorized in the account rather than only this API’s secrets. Authentication performed inside the application was not collected.
- **Remediation:** Change the IAM statement from resource `"*"` to the exact secret ARNs required by the API and set `instance_metadata.http_tokens` to `required`. If `/api/*` is not intended for anonymous Internet clients, add an `authenticate-oidc` or `authenticate-cognito` action before forwarding, or restrict the load balancer security-group sources.

### 3. CI runner can grant arbitrary IAM permissions
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-05c7303bdd00c9384` (brightpath-ci-runner)
- **Evidence:** In us-east-1, role `arn:aws:iam::111122223333:role/brightpath-ci-runner` allows `iam:AttachRolePolicy` and `iam:PutRolePolicy` on resource `"*"`, with no conditions or permissions boundary. The running instance can obtain this role’s credentials through its attached instance profile.
- **Why it matters:** Anyone controlling the instance credentials could modify arbitrary roles, including granting administrator permissions, resulting in account-wide privilege escalation.
- **Remediation:** Remove `iam:AttachRolePolicy` and `iam:PutRolePolicy` on `"*"`. If IAM deployment is required, restrict actions to explicit deployment-role ARNs, constrain permitted policies through conditions and a permissions boundary, and prevent the runner from modifying its own role.

### 4. Analytics notebook has unrestricted S3 control
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-08149cc23245c497a` (brightpath-analytics-notebook)
- **Evidence:** In us-east-1, role `arn:aws:iam::111122223333:role/brightpath-analytics-notebook` has an inline statement allowing `s3:*` on `"*"`. Security group `sg-037fdf8c5d0449baf` also permits TCP/8888 from the entire private range `10.0.0.0/8`.
- **Why it matters:** Compromise of the notebook or its credentials could permit reading, changing, or deleting S3 data belonging to other workloads across the account.
- **Remediation:** Replace `s3:*` on `"*"` with the exact required actions and bucket/object ARNs. Narrow TCP/8888 access to a dedicated administrator security group or specific management CIDRs.

### 5. Image resizer permits IMDSv1 credential requests
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-0e68769e2bc668ceb` (brightpath-image-resizer)
- **Evidence:** In us-east-1, `instance_metadata.http_tokens` is `optional` and the hop limit is `2`, so IMDSv1 requests are accepted. Its role can read and list `arn:aws:s3:::brightpath-media-uploads-111122223333` and its objects, although security group `sg-00e85873169a4dd0b` has no ingress rules.
- **Why it matters:** If a local process or another unshown request-forgery path can reach metadata, temporary credentials could be stolen and used to read the media bucket.
- **Remediation:** Set `instance_metadata.http_tokens` to `required`; use hop limit `1` unless a demonstrated container or proxy requirement needs a higher value. The end state should reject all IMDSv1 requests.

### 6. Reporting worker root volume is unencrypted
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected instances:** `i-03f957210c4d02d7f` (brightpath-reporting-worker)
- **Evidence:** In us-east-1, root volume `vol-0db09f8ba141ddec7` reports `encrypted: false` and `kms_key_id: null`. The volume is an attached 8-GiB EBS root device.
- **Why it matters:** Data on the volume lacks EBS encryption at rest, increasing exposure if the volume or a derived snapshot becomes accessible.
- **Remediation:** Create an encrypted snapshot copy and replace or relaunch the instance with an encrypted root volume using an approved KMS key. Enable EBS encryption by default so replacement volumes and snapshots are encrypted.
