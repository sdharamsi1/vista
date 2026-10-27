# RDS Security Review

## Account Risk Summary
Reviewed 8 DB instances, 0 clusters, 1 RDS Proxy, and 1 manual snapshot, all in us-east-1 (account 111122223333). The posture is undermined by a manual snapshot shared publicly with all AWS accounts and a Postgres instance reachable from the Internet on 0.0.0.0/0:5432, plus several instances with TLS enforcement disabled or storage unencrypted.

## Top Findings

### 1. Manual, unencrypted snapshot shared with all AWS accounts
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual instance snapshot of `brightpath-staging-db` has `shared_with: ["all"]` and `encrypted: false` with `kms_key_id: null`, so no KMS key policy constrains access.
- **Why it matters:** Any AWS account can copy and restore this snapshot and read the full Postgres dataset it contains, giving cross-account data disclosure with no credentials needed.
- **Remediation:** Run `modify-db-snapshot-attribute --attribute-name restore --values-to-remove all` so the snapshot is private, and recreate the snapshot encrypted with the customer-managed KMS key before re-sharing with specific account IDs only.

### 2. CRM Postgres instance reachable from the entire Internet on port 5432
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnets subnet-0f44bd86ce6462af4 / subnet-0fd2d728f4e981a24, route table rtb-016da306f2c809958 with a 0.0.0.0/0 route to igw-0ea6103b8cbc8a1db); security group sg-079c850c8c2093b98 allows tcp 5432 from 0.0.0.0/0 and NACL acl-0addf37833ef9393b allows all ingress/egress.
- **Why it matters:** The database endpoint resolves to a public IP and accepts connection attempts from anywhere, exposing the Postgres authentication surface and all CRM data behind it to unrestricted credential attacks.
- **Remediation:** Set `publicly_accessible: false`, move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in sg-079c850c8c2093b98 with the application tier security group or the 10.81.0.0/16 CIDR.

### 3. BI reporting Postgres instance has a public endpoint gated only by one source IP
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` whose route table rtb-016da306f2c809958 routes 0.0.0.0/0 to igw-0ea6103b8cbc8a1db; sg-0935efccebc93d552 allows tcp 5432 only from 203.0.113.10/32 ("Office BI tool").
- **Why it matters:** The instance is Internet-routable, so any change or broadening of that single ingress rule, or access from that office address, directly exposes the reporting database; no VPN or private path is in place.
- **Remediation:** Set `publicly_accessible: false` and reach the instance over private connectivity (VPN/Direct Connect or a bastion/proxy in 10.81.0.0/16), keeping sg-0935efccebc93d552 limited to internal sources.

### 4. TLS/SSL not required for client connections on two instances
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl: "0"` and `brightpath-legacy-inventory-db` sets `require_secure_transport: "0"`; both are explicit user modifications away from enforcing encrypted transport.
- **Why it matters:** The engines will accept plaintext sessions, so any party with a position on the VPC network path can read credentials and query data in transit.
- **Remediation:** Set `rds.force_ssl=1` on the billing parameter group and `require_secure_transport=1` on the legacy-inventory group, reboot the instances, and verify clients connect with TLS (`sslmode=verify-full` / `--ssl-mode=VERIFY_IDENTITY`).

### 5. RDS Proxy accepts plaintext connections and logs SQL statements in debug mode
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy has `require_tls: false` and `debug_logging: true`; it fronts `brightpath-orders-db` using the RDS-managed master secret (`rds!db-0bd5ab11-...-L96HJu`) with `iam_auth: DISABLED`, and ingress sg-094d5a4fcde67f5a4 allows tcp 5432 from 10.81.0.0/16.
- **Why it matters:** Any host in 10.81.0.0/16 may connect without TLS, and debug logging writes detailed SQL statements (potentially including data values) to CloudWatch Logs readable by any principal with log read permissions.
- **Remediation:** Set `require_tls: true` and `debug_logging: false` on the proxy, and consider enabling IAM authentication on the proxy auth entry instead of password-only access.

### 6. Storage encryption at rest disabled on two instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both have `storage_encrypted: false` and `kms_key_id: null`, while the other six instances use customer-managed key arn:aws:kms:us-east-1:111122223333:key/a343a413-1375-4d20-b1e5-78c139bf45a2.
- **Why it matters:** Volumes, automated backups, and snapshots of these instances are unencrypted, so no KMS key policy gates access to their data copies (as already seen with the publicly shared staging snapshot).
- **Remediation:** Create an encrypted snapshot copy with the customer-managed KMS key and restore each instance from it, ending with `storage_encrypted: true` on all instances.

### 7. Legacy inventory MySQL instance lacks IAM auth, managed master secret, and log exports
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false`, `master_user_secret: null` (master password for `dbadmin` managed outside Secrets Manager), `log_exports: []`, and `backup_retention_days: 1`, unlike the seven Postgres instances which use IAM auth, RDS-managed secrets, and postgresql/upgrade log exports.
- **Why it matters:** A statically held master password with no exported audit logs means credential misuse against this database would be unrotatable by RDS and largely untraceable.
- **Remediation:** Enable `manage-master-user-password` (Secrets Manager) and `iam_auth_enabled: true`, export `audit`/`error`/`general` logs to CloudWatch, and raise backup retention to at least 7 days.

### 8. Deletion protection disabled on all eight DB instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Every instance reports `deletion_protection: false`; `multi_az: false` on all of them and `backup_retention_days: 1` on `brightpath-legacy-inventory-db`.
- **Why it matters:** A principal with rds:DeleteDBInstance (such as the AdministratorAccess SSO role used for this scan) can destroy any of these databases in one call, with only short backup windows for recovery.
- **Remediation:** Set `deletion_protection: true` on all production instances and restrict `rds:DeleteDBInstance`/`rds:ModifyDBInstance` via an SCP or IAM policy to a break-glass role.
