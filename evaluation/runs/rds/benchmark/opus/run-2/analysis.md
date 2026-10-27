# RDS Security Review

## Account Risk Summary
Reviewed 8 DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot, all in us-east-1 (account 111122223333). The posture is undermined by a manual snapshot shared publicly with all AWS accounts, one PostgreSQL instance reachable from the Internet with an unrestricted 0.0.0.0/0 ingress rule, and several instances with TLS enforcement disabled, unencrypted storage, and no deletion protection.

## Top Findings

### 1. Manual snapshot shared with all AWS accounts and unencrypted
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual snapshot has `shared_with: ["all"]`, `encrypted: false` and `kms_key_id: null`, and was taken from instance `brightpath-staging-db` (engine postgres).
- **Why it matters:** Any AWS account can copy and restore this snapshot and read the full database contents offline; because it is unencrypted there is no KMS key policy that would block a cross-account restore.
- **Remediation:** Remove the `all` entry from the snapshot's restore attribute (ModifyDBSnapshotAttribute with ValuesToRemove=all) so it is shared with no accounts, and recreate it encrypted with a customer-managed KMS key if it must be retained.

### 2. Internet-reachable PostgreSQL instance with 0.0.0.0/0 ingress on port 5432
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnets subnet-0f44bd86ce6462af4, subnet-0fd2d728f4e981a24), whose route table rtb-016da306f2c809958 has 0.0.0.0/0 to igw-0ea6103b8cbc8a1db; SG sg-079c850c8c2093b98 allows tcp 5432 from 0.0.0.0/0 ("Remote access") and NACL acl-0addf37833ef9393b allows all ingress/egress.
- **Why it matters:** The database endpoint is directly exposed to the entire Internet for password/credential attacks and any engine-level network exposure, with only database authentication in the path.
- **Remediation:** Set `publicly_accessible` to false and move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in sg-079c850c8c2093b98 with the specific application security group on port 5432.

### 3. Internet-facing BI instance restricted only by a single-IP security group rule
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` with IGW route rtb-016da306f2c809958; SG sg-0935efccebc93d552 allows tcp 5432 only from 203.0.113.10/32 ("Office BI tool").
- **Why it matters:** The endpoint resolves to a public IP, so all protection rests on one source-IP rule; any change to that rule or control of that address yields direct Internet access to the database.
- **Remediation:** Set `publicly_accessible` to false, place the instance in `brightpath-db-private`, and reach it over VPN/Direct Connect or a bastion instead of a public source-IP allowance.

### 4. TLS/SSL not required for client connections on two instances and the RDS Proxy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl: "0"`; `brightpath-legacy-inventory-db` sets `require_secure_transport: "0"`; proxy `brightpath-orders-db-proxy` has `require_tls: false` while authenticating with the orders DB secret (POSTGRES_SCRAM_SHA_256).
- **Why it matters:** These endpoints accept plaintext connections, so an attacker with a network position in VPC vpc-0de19d260a9ad9f27 can capture credentials and query data in transit.
- **Remediation:** Set `rds.force_ssl=1`, `require_secure_transport=1`, and the proxy's `require_tls=true`, so all three endpoints reject non-TLS client connections.

### 5. Legacy MySQL instance uses static master password, no IAM auth, broad /8 ingress, and minimal backup/logging
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false`, `master_user_secret: null` (master password not Secrets Manager–managed), `log_exports: []`, `backup_retention_days: 1`, and SG sg-0c297cdba6b8b1a6b allows tcp 3306 from 10.0.0.0/8 although the VPC CIDR is 10.81.0.0/16.
- **Why it matters:** A long-lived, unrotated master password combined with ingress far wider than the VPC and no database log exports makes credential misuse easy and after-the-fact detection impossible, with only 1 day of recovery window.
- **Remediation:** Enable IAM database authentication and RDS-managed master password rotation, narrow sg-0c297cdba6b8b1a6b ingress to the specific application security group, enable `error`/`general`/`audit` log exports, and raise `backup_retention_days` to at least 7.

### 6. RDS Proxy debug logging exposes SQL statement detail
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true` and fronts `brightpath-orders-db` via secret arn:aws:secretsmanager:...rds!db-0bd5ab11-173c-4678-a1c1-ccac1e662568-L96HJu; `iam_auth: DISABLED` on its auth entry.
- **Why it matters:** Detailed SQL statements, which can include query values from the orders database, are written to CloudWatch logs where anyone with log-read permissions can see them.
- **Remediation:** Set `debug_logging` to false on the proxy, leaving it enabled only for short, scoped troubleshooting windows.

### 7. Unencrypted storage on two PostgreSQL instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both have `storage_encrypted: false` and `kms_key_id: null`, while the other instances use customer-managed key arn:aws:kms:us-east-1:111122223333:key/a343a413-1375-4d20-b1e5-78c139bf45a2 (key_manager CUSTOMER, Enabled).
- **Why it matters:** Data at rest, automated backups, and any snapshots of these instances carry no KMS protection, so copies can be restored without any key-policy authorization check (as already seen with the public staging snapshot).
- **Remediation:** Create encrypted copies (snapshot, copy with the customer-managed KMS key, restore) and replace these instances so `storage_encrypted` is true.

### 8. Deletion protection disabled on all DB instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Every instance reports `deletion_protection: false`; backup retention is 7 days except `brightpath-legacy-inventory-db` at 1 day.
- **Why it matters:** An actor or error with RDS delete permissions can destroy any of these databases immediately, with recovery limited to the automated backup window.
- **Remediation:** Set `deletion_protection: true` on all eight instances so DeleteDBInstance is rejected until protection is explicitly removed.
