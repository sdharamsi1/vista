# RDS Security Review

## Account Risk Summary
The account has a critical cross-account data exposure through a publicly shared, unencrypted snapshot and one database directly exposed to the Internet. The review covered 8 DB instances, 0 clusters, 1 proxy, and 1 manual snapshot in us-east-1.

## Top Findings

### 1. Unencrypted manual snapshot is publicly restorable
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (manual snapshot, us-east-1)
- **Evidence:** The snapshot has `shared_with:["all"]`, allowing any AWS account to copy or restore it. It is also unencrypted (`encrypted:false`, `kms_key_id:null`).
- **Why it matters:** Any AWS account can obtain a copy of the snapshot and access the database contents outside this account's controls.
- **Remediation:** Immediately remove `all` from the snapshot's restore attribute. Create an encrypted copy using an enabled customer-managed KMS key, retain only the encrypted private copy, and delete the unencrypted public snapshot after validation.

### 2. PostgreSQL database is reachable from the entire Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible:true`, and security group `sg-079c850c8c2093b98` permits TCP port 5432 from `0.0.0.0/0`. Its subnets use route table `rtb-016da306f2c809958`, which has an active `0.0.0.0/0` route to Internet gateway `igw-0ea6103b8cbc8a1db`; network ACL `acl-0addf37833ef9393b` allows all ingress and egress.
- **Why it matters:** Any Internet host can establish network connections to the PostgreSQL listener and attempt authentication or abuse valid credentials.
- **Remediation:** Set `publicly_accessible` to `false`, place the instance in `brightpath-db-private`, and replace the `0.0.0.0/0` ingress rule with only the specific application security groups or private CIDRs that require access.

### 3. Deletion protection is disabled across every DB instance
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-billing-db` (DB instance, us-east-1), `brightpath-bi-reporting-db` (DB instance, us-east-1), `brightpath-crm-db` (DB instance, us-east-1), `brightpath-events-db` (DB instance, us-east-1), `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** All eight instances have `deletion_protection:false`. Backup retention is only 1 day for `brightpath-legacy-inventory-db` and 7 days for the other instances.
- **Why it matters:** A principal that obtains destructive RDS permissions can delete these databases without the deletion-protection guardrail, causing a bounded but meaningful availability and recovery impact.
- **Remediation:** Set `deletion_protection` to `true` on every instance. Restrict `rds:DeleteDBInstance` and `rds:ModifyDBInstance` permissions to tightly controlled administrative roles.

### 4. RDS Proxy debug logging may expose SQL details
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** The active proxy has `debug_logging:true`, causing detailed SQL statement information to be written to its logs. The supplied data does not include the permissions controlling access to those logs.
- **Why it matters:** A principal with log-reading access could obtain query details and potentially data values or operational information associated with the orders database.
- **Remediation:** Set `debug_logging` to `false` except during time-bounded troubleshooting. Restrict access to the proxy's log group, configure an appropriate retention period, and remove previously retained debug logs when no longer required.

### 5. Two DB instances lack encryption at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Both instances have `storage_encrypted:false` and `kms_key_id:null`. The remaining six instances are encrypted.
- **Why it matters:** Database storage and associated backups lack KMS-backed protection, increasing data exposure if an attacker obtains the necessary storage or RDS control-plane access.
- **Remediation:** Snapshot each instance, copy the snapshot with encryption enabled under an enabled customer-managed KMS key, and restore or migrate to an encrypted instance. The final instances and all retained snapshots should have encryption enabled.

### 6. Database connections are permitted without mandatory TLS
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (DB instance, us-east-1), `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** `brightpath-billing-db` explicitly sets `rds.force_ssl:"0"`, and `brightpath-legacy-inventory-db` sets `require_secure_transport:"0"`. The proxy has `require_tls:false` and accepts clients from `10.81.0.0/16` on TCP port 5432.
- **Why it matters:** Clients can use plaintext database connections, allowing credentials, queries, or returned data to be exposed if an attacker first gains visibility into the relevant network path.
- **Remediation:** Set `rds.force_ssl=1` for `brightpath-billing-db`, `require_secure_transport=1` for `brightpath-legacy-inventory-db`, and `require_tls=true` for `brightpath-orders-db-proxy`. Require clients to validate the RDS CA certificate before removing support for non-TLS connections.
