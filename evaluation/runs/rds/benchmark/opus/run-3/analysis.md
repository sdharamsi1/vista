# RDS Security Review

## Account Risk Summary
Reviewed 8 RDS DB instances, 0 clusters, 1 RDS Proxy, and 1 manual snapshot, all in us-east-1 (account 111122223333). Posture is mixed: most databases sit in private subnets with empty ingress rules, but one manual snapshot is shared with all AWS accounts, one PostgreSQL instance is Internet-reachable from 0.0.0.0/0, and several instances disable TLS enforcement or storage encryption.

## Top Findings

### 1. Manual snapshot shared publicly with all AWS accounts
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual instance snapshot of `brightpath-staging-db` has `shared_with: ["all"]` and `encrypted: false` (`kms_key_id` null), so it is unencrypted and restorable by any AWS account.
- **Why it matters:** Any AWS principal worldwide can copy or restore the snapshot and read the full PostgreSQL database contents offline, with no need for network or credential access.
- **Remediation:** Run `modify-db-snapshot-attribute --attribute restore --values-to-remove all` so the snapshot is private, and recreate it from an encrypted source using a customer-managed KMS key.

### 2. PostgreSQL instance reachable from the entire Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnets `subnet-0f44bd86ce6462af4`/`subnet-0fd2d728f4e981a24`, route table `rtb-016da306f2c809958` with a 0.0.0.0/0 route to `igw-0ea6103b8cbc8a1db`); security group `sg-079c850c8c2093b98` allows tcp 5432 from `0.0.0.0/0`, and NACL `acl-0addf37833ef9393b` allows all ingress/egress.
- **Why it matters:** The database endpoint accepts connection attempts from any Internet host, exposing the `dbadmin` login to unrestricted brute-force and direct data access if credentials are obtained.
- **Remediation:** Set `publicly_accessible: false`, move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in `sg-079c850c8c2093b98` with the application security group or specific CIDRs on port 5432.

### 3. Internet-facing BI instance limited only by a single source CIDR
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` whose route table `rtb-016da306f2c809958` routes 0.0.0.0/0 to `igw-0ea6103b8cbc8a1db`; security group `sg-0935efccebc93d552` permits tcp 5432 only from `203.0.113.10/32` ("Office BI tool").
- **Why it matters:** The endpoint resolves to a public IP, so any compromise of or change to that single allow-listed source, or a rule widening, directly exposes the database to the Internet.
- **Remediation:** Set `publicly_accessible: false` and relocate to `brightpath-db-private`, reaching the instance over VPN/Direct Connect or a bastion instead of a public endpoint.

### 4. TLS enforcement explicitly disabled on two databases
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl: "0"`, and parameter group `brightpath-legacy-inventory-db` sets `require_secure_transport: "0"`, so both instances accept non-TLS client connections.
- **Why it matters:** Credentials and query data can traverse the VPC in cleartext, readable by anyone able to observe or intercept traffic on the network path.
- **Remediation:** Set `rds.force_ssl=1` on `brightpath-billing-db` and `require_secure_transport=1` on `brightpath-legacy-inventory-db` and reboot, so only TLS connections are accepted.

### 5. RDS Proxy accepts plaintext connections and logs SQL statements
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy has `require_tls: false` and `debug_logging: true`; it fronts `brightpath-orders-db` using Secrets Manager secret `rds!db-0bd5ab11-173c-4678-a1c1-ccac1e662568-L96HJu` with `iam_auth: DISABLED`, and ingress on `sg-094d5a4fcde67f5a4` is tcp 5432 from `10.81.0.0/16`.
- **Why it matters:** Client sessions from the app tier may be unencrypted, and debug logging writes detailed SQL statements (potentially including data values) to logs accessible to anyone with CloudWatch Logs read permission.
- **Remediation:** Set `require_tls: true` and `debug_logging: false` on the proxy, and enable IAM authentication for proxy connections.

### 6. Unencrypted storage on two PostgreSQL instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both have `storage_encrypted: false` and `kms_key_id: null`, unlike the other six instances which use customer-managed key `a343a413-1375-4d20-b1e5-78c139bf45a2` (key_manager CUSTOMER, Enabled).
- **Why it matters:** Data at rest and their automated backups/snapshots carry no KMS protection, so key-policy controls cannot restrict access to restored copies.
- **Remediation:** Create an encrypted snapshot copy with the customer-managed KMS key and restore each instance from it so `storage_encrypted` is true.

### 7. Deletion protection disabled account-wide and minimal backup retention on one instance
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** All eight instances have `deletion_protection: false`; `brightpath-legacy-inventory-db` additionally has `backup_retention_days: 1` versus 7 on the others, and `multi_az: false` on every instance.
- **Why it matters:** A single API call by any principal with rds:DeleteDBInstance can destroy a database, and the 1-day retention leaves almost no window for point-in-time recovery.
- **Remediation:** Enable `deletion_protection` on all eight instances and raise `backup_retention_days` on `brightpath-legacy-inventory-db` to match the 7-day (or longer) standard.

### 8. Legacy MySQL instance lacks IAM authentication, managed master secret, and log exports
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false`, `master_user_secret: null`, and `log_exports: []`, while the seven PostgreSQL instances all have `iam_auth_enabled: true`, active `master_user_secret` entries, and export `postgresql`/`upgrade` logs; ingress on `sg-0c297cdba6b8b1a6b` is tcp 3306 from `10.0.0.0/8`.
- **Why it matters:** The `dbadmin` password is managed outside Secrets Manager with no rotation evidence and no database logs are shipped, so credential misuse from the broad private range would be hard to detect.
- **Remediation:** Enable IAM database authentication and RDS-managed master password (Secrets Manager), export `error`/`general`/`slowquery` logs to CloudWatch, and narrow the 10.0.0.0/8 ingress rule to the application security group.
