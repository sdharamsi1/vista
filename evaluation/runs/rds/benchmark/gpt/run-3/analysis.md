# RDS Security Review

## Account Risk Summary
The account has one publicly shared unencrypted snapshot and one database exposed to the entire Internet, creating the most significant risks. The review covered 8 DB instances, 0 clusters, 1 proxy, and 1 manual snapshot, all in us-east-1.

## Top Findings

### 1. Unencrypted snapshot is publicly available to every AWS account
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual snapshot has `shared_with: ["all"]`, `encrypted: false`, and `kms_key_id: null`. Any AWS account can copy or restore it.
- **Why it matters:** This provides direct cross-account access to all database contents captured in the snapshot.
- **Remediation:** Remove `"all"` from the snapshot restore attribute immediately. Create a KMS-encrypted copy if the snapshot must be retained, restrict any sharing to explicitly authorized account IDs, and delete the publicly shared unencrypted copy.

### 2. PostgreSQL database is exposed to the entire Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true`; its public subnets use route table `rtb-016da306f2c809958` with active `0.0.0.0/0` routing to Internet gateway `igw-0ea6103b8cbc8a1db`. Security group `sg-079c850c8c2093b98` permits TCP port 5432 from `0.0.0.0/0`, and the subnet network ACL allows all ingress and egress.
- **Why it matters:** Any Internet host can reach the PostgreSQL authentication interface and attempt unauthorized access against this database.
- **Remediation:** Set `publicly_accessible` to `false`, place the instance only in subnets without an Internet-gateway route, and replace the `0.0.0.0/0` rule with access from narrowly scoped application security groups or private network CIDRs.

### 3. Reporting database has a publicly reachable endpoint
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true` and uses public subnets whose route table sends `0.0.0.0/0` to Internet gateway `igw-0ea6103b8cbc8a1db`. Security group `sg-0935efccebc93d552` permits TCP port 5432 from the external CIDR `203.0.113.10/32`.
- **Why it matters:** A party able to originate traffic from the permitted external address can directly reach the database authentication interface.
- **Remediation:** Set `publicly_accessible` to `false`, move connectivity to private VPN, Direct Connect, or other private access, and replace the external CIDR rule with a narrowly scoped security-group or private-CIDR source.

### 4. Proxy debug logging can place SQL details in logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true`, causing detailed SQL statement information to be included in its logs. Log-destination permissions and retention controls were not supplied.
- **Why it matters:** Principals with access to these logs could obtain queries and potentially sensitive values associated with the orders database.
- **Remediation:** Set proxy `DebugLogging` to `false` outside short, controlled troubleshooting windows. Restrict log access to designated operators and apply an appropriate retention period to any existing debug logs.

### 5. Database and proxy endpoints explicitly permit plaintext connections
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (instance, us-east-1), `brightpath-legacy-inventory-db` (instance, us-east-1), `brightpath-orders-db-proxy` (proxy, us-east-1)
- **Evidence:** `brightpath-billing-db` explicitly sets PostgreSQL `rds.force_ssl` to `"0"`; `brightpath-legacy-inventory-db` explicitly sets MySQL `require_secure_transport` to `"0"`; and `brightpath-orders-db-proxy` has `require_tls: false`. The legacy instance allows port 3306 from `10.0.0.0/8`, while the proxy allows port 5432 from `10.81.0.0/16`; the billing instance currently has no security-group ingress rules.
- **Why it matters:** Clients can establish unencrypted sessions, exposing credentials, queries, or returned data if an attacker can observe or intercept permitted network traffic.
- **Remediation:** Set PostgreSQL `rds.force_ssl=1`, MySQL `require_secure_transport=1`, and proxy `RequireTLS=true`. Confirm all clients trust the RDS CA and connect successfully over TLS before enforcing these settings.

### 6. Two DB instances lack encryption at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (instance, us-east-1), `brightpath-staging-db` (instance, us-east-1)
- **Evidence:** Both instances have `storage_encrypted: false` and `kms_key_id: null`.
- **Why it matters:** Their database storage and associated backups do not receive RDS KMS encryption-at-rest protection, increasing exposure if storage artifacts become accessible.
- **Remediation:** Snapshot each instance, create a KMS-encrypted snapshot copy, and restore or migrate to a replacement instance with `StorageEncrypted=true` and an approved KMS key. Retire the unencrypted instances and snapshots after validating the migration.
