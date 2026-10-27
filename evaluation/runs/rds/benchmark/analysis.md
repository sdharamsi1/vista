# RDS Security Review

## Account Risk Summary
Reviewed 8 RDS DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot in us-east-1 (account 111122223333). The posture is undermined by a manual snapshot shared publicly with all AWS accounts, a PostgreSQL instance reachable from 0.0.0.0/0 on port 5432 in an Internet-gateway-routed subnet, and several instances/proxy that do not enforce TLS or storage encryption.

## Top Findings

### 1. Manual snapshot shared with all AWS accounts and unencrypted
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual snapshot of `brightpath-staging-db` has `shared_with: ["all"]` and `encrypted: false` with `kms_key_id: null`, so any AWS account can copy or restore it without needing any KMS grant.
- **Why it matters:** Any AWS principal in any account can restore the snapshot and read the full contents of the staging PostgreSQL database, giving unrestricted cross-account data disclosure.
- **Remediation:** Remove the "all" entry from the snapshot's restore attribute (`modify-db-snapshot-attribute --attribute-name restore --values-to-remove all`), and re-create the snapshot encrypted with the customer-managed KMS key before any intentional sharing with specific account IDs.

### 2. brightpath-crm-db is Internet-reachable from any source on port 5432
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnets subnet-0f44bd86ce6462af4 / subnet-0fd2d728f4e981a24, route table rtb-016da306f2c809958 with a 0.0.0.0/0 route to igw-0ea6103b8cbc8a1db); security group sg-079c850c8c2093b98 allows tcp 5432 from 0.0.0.0/0 ("Remote access") and NACL acl-0addf37833ef9393b allows all ingress/egress.
- **Why it matters:** The PostgreSQL endpoint is open to the entire Internet for credential brute-forcing and direct connection attempts against this database's data.
- **Remediation:** Set `publicly_accessible: false` and move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in sg-079c850c8c2093b98 with the specific application security group or VPC CIDR on port 5432.

### 3. brightpath-bi-reporting-db exposed to the Internet behind a single-IP allowlist
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` whose route table rtb-016da306f2c809958 routes 0.0.0.0/0 to igw-0ea6103b8cbc8a1db; sg-0935efccebc93d552 permits tcp 5432 only from 203.0.113.10/32 ("Office BI tool").
- **Why it matters:** The database endpoint resolves to a public IP, so any change or compromise of the allowlisted office egress address exposes the reporting database directly to the Internet.
- **Remediation:** Set `publicly_accessible: false`, place the instance in `brightpath-db-private`, and reach it over VPN/Direct Connect or a bastion so no Internet path to port 5432 exists.

### 4. TLS/SSL not enforced on two databases and the RDS Proxy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl=0`, parameter group `brightpath-legacy-inventory-db` sets `require_secure_transport=0`, and the proxy `brightpath-orders-db-proxy` has `require_tls: false` with auth scheme SECRETS/POSTGRES_SCRAM_SHA_256.
- **Why it matters:** Clients may connect in cleartext, so credentials and query data can be read or altered by anyone able to observe or intercept traffic on the VPC path.
- **Remediation:** Set `rds.force_ssl=1`, `require_secure_transport=1`, and `require_tls: true` on the proxy, so all three endpoints accept only TLS connections.

### 5. RDS Proxy debug logging records SQL statement detail
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy fronting `brightpath-orders-db` has `debug_logging: true`, which makes it emit detailed information about SQL statements into its logs.
- **Why it matters:** Query text and embedded values from the orders database are written to logs, so any principal with read access to those logs can obtain database content without connecting to the database.
- **Remediation:** Set `debug_logging: false` on `brightpath-orders-db-proxy` and keep it enabled only for time-bounded troubleshooting.

### 6. Storage encryption disabled on two PostgreSQL instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both instances report `storage_encrypted: false` and `kms_key_id: null`, while the other six instances use the customer-managed key arn:aws:kms:us-east-1:111122223333:key/a343a413-1375-4d20-b1e5-78c139bf45a2.
- **Why it matters:** Volumes, automated backups, and snapshots of these databases are stored without KMS encryption, removing key-based access control over data at rest (as already seen with the unencrypted public snapshot).
- **Remediation:** Create an encrypted snapshot copy with the customer-managed KMS key and restore each instance from it so `storage_encrypted` is true for all instances.

### 7. brightpath-legacy-inventory-db uses self-managed credentials, broad internal ingress, no IAM auth and minimal backups/logging
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false`, `master_user_secret: null` (master password not managed in Secrets Manager), `log_exports: []`, `backup_retention_days: 1`, and sg-0c297cdba6b8b1a6b allows tcp 3306 from 10.0.0.0/8 — far wider than the VPC CIDR 10.81.0.0/16.
- **Why it matters:** A static, unmanaged master password reachable from any 10/8 address with no exported logs and a 1-day backup window makes unauthorized access harder to detect and recover from.
- **Remediation:** Enable `manage_master_user_password` and IAM database authentication, narrow the sg-0c297cdba6b8b1a6b ingress to the specific app security group, enable error/general/slowquery log exports, and raise backup retention to at least 7 days.

### 8. Deletion protection disabled on all DB instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** All eight instances report `deletion_protection: false`; `brightpath-legacy-inventory-db` additionally has only `backup_retention_days: 1`.
- **Why it matters:** Any principal with rds:DeleteDBInstance can destroy these databases immediately, with limited recovery window for the 1-day-retention instance.
- **Remediation:** Set `deletion_protection: true` on all production instances so deletion requires an explicit configuration change first.
