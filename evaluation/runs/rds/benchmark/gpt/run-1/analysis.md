# RDS Security Review

## Account Risk Summary
The account has a critical cross-account data exposure through a public manual snapshot and a high-risk Internet-accessible database. The review covered 8 DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot in us-east-1.

## Top Findings

### 1. Unencrypted manual snapshot is public to every AWS account
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (manual snapshot, us-east-1)
- **Evidence:** The snapshot has `shared_with=["all"]`, `encrypted=false`, and `kms_key_id=null`.
- **Why it matters:** Any AWS account can copy or restore this snapshot, creating direct cross-account access to its database contents.
- **Remediation:** Remove `"all"` from the snapshot restore attribute immediately. Create an encrypted copy using an enabled customer-managed KMS key, verify that it has no unintended account shares, and delete the public unencrypted snapshot.

### 2. PostgreSQL database is directly exposed to the Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible=true`; its public subnets use route table `rtb-016da306f2c809958` with an active `0.0.0.0/0` Internet gateway route. Security group `sg-079c850c8c2093b98` permits TCP port 5432 from `0.0.0.0/0`, and the subnet ACL permits all ingress and egress.
- **Why it matters:** Any Internet host can establish network connections to the PostgreSQL listener and attempt authentication or resource-exhaustion attacks.
- **Remediation:** Set `publicly_accessible=false`, place the instance in `brightpath-db-private`, and replace the `0.0.0.0/0` ingress rule with only the specific application security groups or private CIDRs that require database access.

### 3. Public reporting database permits access from an external address
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible=true` and uses public subnets whose route table has an active Internet gateway route. Security group `sg-0935efccebc93d552` permits TCP port 5432 from the non-RFC-1918 address `203.0.113.10/32`.
- **Why it matters:** The database listener is reachable from the permitted external source, so control of that source provides a direct path to attempt database authentication.
- **Remediation:** Set `publicly_accessible=false`, move the instance to `brightpath-db-private`, and provide reporting access through private connectivity such as VPN or Direct Connect with narrowly scoped security-group rules.

### 4. Database and proxy endpoints do not enforce encrypted client transport
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-billing-db` (DB instance, us-east-1), `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** `brightpath-legacy-inventory-db` explicitly sets `require_secure_transport="0"` and permits port 3306 from `10.0.0.0/8`. `brightpath-billing-db` explicitly sets `rds.force_ssl="0"`, although its security group currently has no ingress rules; `brightpath-orders-db-proxy` has `require_tls=false` and permits port 5432 from `10.81.0.0/16`.
- **Why it matters:** Clients can use plaintext connections, allowing credentials or database traffic to be exposed if an attacker obtains an on-path position.
- **Remediation:** Set MySQL `require_secure_transport=1`, PostgreSQL `rds.force_ssl=1`, and the proxy's `require_tls=true`. Require clients to validate the RDS CA certificate and confirm that plaintext connections are rejected.

### 5. Two DB instances and their automated backups lack encryption at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Both instances have `storage_encrypted=false` and `kms_key_id=null`.
- **Why it matters:** Their underlying storage, automated backups, and snapshots do not receive KMS-backed encryption at rest, reducing protection if storage artifacts become accessible.
- **Remediation:** Snapshot each instance, create an encrypted snapshot copy using the enabled customer-managed KMS key, and restore replacement instances from those encrypted copies. Verify the replacements report `storage_encrypted=true` before retiring the originals.

### 6. Proxy debug logging can place detailed SQL information in logs
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging=true`, causing detailed SQL statement information to be included in its logs. The supplied data does not show the statements generated at runtime or who can read the logs.
- **Why it matters:** SQL text, schema details, or values embedded in statements may become available to principals with log-reading access.
- **Remediation:** Set `debug_logging=false` outside narrowly time-bounded troubleshooting. Restrict log-group access and retention, and review existing proxy logs for information that should be removed or protected.

### 7. Deletion protection is disabled across every DB instance
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-billing-db` (DB instance, us-east-1), `brightpath-bi-reporting-db` (DB instance, us-east-1), `brightpath-crm-db` (DB instance, us-east-1), `brightpath-events-db` (DB instance, us-east-1), `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Every reviewed DB instance has `deletion_protection=false`; backup retention is 7 days for seven instances and only 1 day for `brightpath-legacy-inventory-db`.
- **Why it matters:** A principal with sufficient RDS permissions can delete an instance without the additional deletion-protection barrier, causing service disruption and increasing dependence on retained backups.
- **Remediation:** Set `deletion_protection=true` on all persistent instances. Restrict `rds:ModifyDBInstance` and `rds:DeleteDBInstance` permissions, and require a controlled process for disabling protection.
