# RDS Security Review

## Account Risk Summary
The review covered 8 DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot in us-east-1. The most serious risks are a publicly shared unencrypted snapshot and a PostgreSQL instance exposed to the entire Internet.

## Top Findings

### 1. Unencrypted manual snapshot is publicly restorable
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (manual snapshot, us-east-1)
- **Evidence:** The snapshot has `shared_with: ["all"]`, allowing any AWS account to copy or restore it. It also has `encrypted: false` and no KMS key.
- **Why it matters:** This directly permits cross-account acquisition of the snapshot’s database contents without prior access to account 111122223333.
- **Remediation:** Remove the `all` restore permission using `ModifyDBSnapshotAttribute` with `AttributeName=restore` and `ValuesToRemove=all`. Create an encrypted copy under a customer-managed KMS key, restrict restore permissions to explicitly authorized account IDs, and delete the publicly shared unencrypted copy.

### 2. CRM database is exposed to the entire Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true`, and security group `sg-079c850c8c2093b98` permits TCP/5432 from `0.0.0.0/0`. Its subnets use route table `rtb-016da306f2c809958`, which has an active `0.0.0.0/0` route to Internet gateway `igw-0ea6103b8cbc8a1db`; the network ACL allows all ingress and egress.
- **Why it matters:** Any Internet host can establish network connections to the PostgreSQL listener, exposing the database authentication boundary to unsolicited access attempts.
- **Remediation:** Set `PubliclyAccessible` to `false`, move the instance to the private subnet group, and remove the `0.0.0.0/0` TCP/5432 rule. Permit access only from specific application security groups or narrowly scoped private network CIDRs.

### 3. BI reporting database has externally reachable public addressing
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true`; security group `sg-0935efccebc93d552` permits TCP/5432 from `203.0.113.10/32`. Its subnets have an active default route to Internet gateway `igw-0ea6103b8cbc8a1db`, and the network ACL allows all ingress and egress.
- **Why it matters:** A party able to originate traffic from the allowed external address can directly reach the PostgreSQL authentication boundary over the Internet.
- **Remediation:** Set `PubliclyAccessible` to `false`, place the instance in the private subnet group, and replace the external CIDR rule with an application security-group reference or an approved private CIDR reachable through controlled private connectivity.

### 4. Database and proxy clients are allowed to use unencrypted connections
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (DB instance, us-east-1), `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** `brightpath-billing-db` explicitly sets `rds.force_ssl` to `0`, and `brightpath-legacy-inventory-db` explicitly sets `require_secure_transport` to `0`. The proxy has `require_tls: false`; its security group permits TCP/5432 from private CIDR `10.81.0.0/16`.
- **Why it matters:** Clients can connect without TLS, allowing database credentials, queries, or results to be exposed if an attacker can observe or manipulate traffic on an allowed network path.
- **Remediation:** Set `rds.force_ssl=1` for the PostgreSQL instance, `require_secure_transport=1` for the MySQL instance, and `RequireTLS=true` on the proxy. Require clients to validate the RDS CA certificate.

### 5. Two database instances store data without encryption at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Both instances have `storage_encrypted: false` and `kms_key_id: null`.
- **Why it matters:** Database storage and automated backups lack the access-control and cryptographic protections provided by KMS-backed RDS encryption.
- **Remediation:** Snapshot each instance, copy the snapshot with encryption enabled under an approved customer-managed KMS key, and restore a replacement encrypted instance. Require `StorageEncrypted=true` for all replacement and future instances.

### 6. Proxy debug logging can expose detailed SQL content
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true`, which records detailed information about SQL statements in its logs.
- **Why it matters:** Principals with access to the proxy logs may be able to read sensitive values embedded in SQL statements, increasing the consequences of log-access permissions or log export.
- **Remediation:** Set `DebugLogging=false` except during time-bounded troubleshooting. Restrict access to existing proxy logs and apply appropriate retention and deletion controls.

### 7. Legacy database has weak protection against destructive deletion
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (DB instance, us-east-1)
- **Evidence:** The instance has `deletion_protection: false` and only `backup_retention_days: 1`.
- **Why it matters:** A mistaken or malicious control-plane deletion could remove the instance without the deletion-protection guardrail, while the one-day automated-backup window provides limited recovery depth.
- **Remediation:** Set `DeletionProtection=true` and increase `BackupRetentionPeriod` to an approved recovery window, such as at least 7 days. Require and retain a final encrypted snapshot when deletion is explicitly authorized.
