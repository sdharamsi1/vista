# RDS Security Review

## Account Risk Summary
Reviewed 8 DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot, all in us-east-1 (account 111122223333). Posture is mixed: most instances sit in private subnets with no ingress rules, but one manual snapshot is shared with all AWS accounts, one PostgreSQL instance is Internet-reachable on 0.0.0.0/0, and several instances/proxy have TLS enforcement or encryption at rest disabled.

## Top Findings

### 1. Manual snapshot of staging database shared publicly with all AWS accounts
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** The manual instance snapshot `brightpath-staging-db-pre-migration` (source `brightpath-staging-db`, engine postgres) has `shared_with: ["all"]` and `encrypted: false` with `kms_key_id: null`, so no KMS key policy limits who can copy or restore it.
- **Why it matters:** Any AWS account can copy and restore the snapshot and read the full contents of the staging database offline, outside this account's network and IAM controls.
- **Remediation:** Remove the `all` entry from the snapshot's restore attribute (`modify-db-snapshot-attribute --attribute-name restore --values-to-remove all`) so it is shared with no accounts, and delete the snapshot if it is no longer needed.

### 2. CRM PostgreSQL instance publicly accessible with 5432 open to 0.0.0.0/0
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnet-0f44bd86ce6462af4, subnet-0fd2d728f4e981a24), whose route table rtb-016da306f2c809958 has 0.0.0.0/0 to igw-0ea6103b8cbc8a1db; SG sg-079c850c8c2093b98 allows tcp 5432 from 0.0.0.0/0 ("Remote access") and NACL acl-0addf37833ef9393b allows all ingress/egress.
- **Why it matters:** The master user `dbadmin` endpoint is reachable from the entire Internet, exposing the database to credential attacks and any authentication-layer weakness with no network control in front of it.
- **Remediation:** Set `publicly_accessible: false` and move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in sg-079c850c8c2093b98 with the application tier's security group on port 5432.

### 3. BI reporting instance exposed to the Internet, restricted only by a single source IP
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` with an Internet gateway route (rtb-016da306f2c809958 -> igw-0ea6103b8cbc8a1db); SG sg-0935efccebc93d552 permits tcp 5432 only from 203.0.113.10/32 ("Office BI tool").
- **Why it matters:** The endpoint resolves to a public IP, so compromise or reassignment of that single office address, or any egress from it, yields direct database reachability with no VPN or private path required.
- **Remediation:** Set `publicly_accessible: false` and reach the instance over VPN/Direct Connect or a bastion/proxy in the VPC, keeping sg-0935efccebc93d552 ingress limited to internal CIDRs or security groups.

### 4. TLS/SSL not enforced on two databases and the RDS Proxy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl: "0"`; parameter group `brightpath-legacy-inventory-db` sets `require_secure_transport: "0"`; the proxy `brightpath-orders-db-proxy` has `require_tls: false`.
- **Why it matters:** These endpoints accept plaintext sessions, so credentials and query data for the billing, legacy inventory, and orders paths can be read or modified by anyone able to observe or intercept VPC traffic.
- **Remediation:** Set `rds.force_ssl=1` on brightpath-billing-db, `require_secure_transport=1` on brightpath-legacy-inventory-db, and `require_tls=true` on brightpath-orders-db-proxy so only TLS connections are accepted.

### 5. Storage encryption at rest disabled on two PostgreSQL instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both instances report `storage_encrypted: false` and `kms_key_id: null`, while the other six instances use customer-managed key arn:aws:kms:us-east-1:111122223333:key/a343a413-1375-4d20-b1e5-78c139bf45a2 (key_manager CUSTOMER, Enabled).
- **Why it matters:** Volumes, automated backups, and any snapshots of these instances are stored unencrypted, so no KMS key policy gates access to copies of the data (as already demonstrated by the unencrypted public snapshot).
- **Remediation:** Create encrypted copies (snapshot -> copy with the customer-managed KMS key -> restore) and retire the unencrypted instances, ending with `storage_encrypted: true` on every instance.

### 6. RDS Proxy logs SQL statement detail and does not use IAM authentication
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true`, `default_auth_scheme: "NONE"`, and its single auth entry uses SECRETS with `iam_auth: "DISABLED"` against secret rds!db-0bd5ab11-173c-4678-a1c1-ccac1e662568.
- **Why it matters:** Detailed SQL statements, which can contain sensitive data values, are written to CloudWatch Logs where any principal with log read access can see them, and client access depends solely on the database password rather than IAM identity.
- **Remediation:** Set `debug_logging: false` on brightpath-orders-db-proxy and enable `iam_auth: REQUIRED` for its secret-based auth entry so clients authenticate with IAM tokens.

### 7. Legacy MySQL instance uses an unmanaged master password, no IAM auth, no log exports, and 1-day backups
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false`, `master_user_secret: null` for master user `dbadmin`, `log_exports: []`, and `backup_retention_days: 1`; ingress in sg-0c297cdba6b8b1a6b allows tcp 3306 from the broad private range 10.0.0.0/8.
- **Why it matters:** A static, non-rotated master password combined with no audit/error log export leaves database authentication unverifiable and attacks untraceable, and a 1-day retention window limits recovery after destructive access.
- **Remediation:** Enable RDS-managed master password in Secrets Manager (or rotate it externally), turn on IAM database authentication, enable error/general/slowquery log exports, raise `backup_retention_days` to at least 7, and narrow sg-0c297cdba6b8b1a6b to the application security group.

### 8. Deletion protection disabled on all eight DB instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Every instance reports `deletion_protection: false`; `multi_az: false` on all eight, and `backup_retention_days` is 7 for seven of them and 1 for brightpath-legacy-inventory-db.
- **Why it matters:** Any principal with rds:DeleteDBInstance can destroy a production database in a single API call, with recovery limited to the retained automated backups.
- **Remediation:** Set `deletion_protection: true` on all eight instances and restrict rds:DeleteDBInstance to a controlled role.
