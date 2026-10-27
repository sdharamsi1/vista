# RDS Security Review

## Account Risk Summary
The review covered 8 DB instances, 0 DB clusters, 1 RDS Proxy, and 1 manual snapshot in us-east-1. The most serious risks are an unencrypted snapshot shared publicly with every AWS account and a PostgreSQL instance directly reachable from the Internet.

## Top Findings

### 1. Unencrypted manual snapshot is publicly shared
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual snapshot has `shared_with: ["all"]`, `encrypted: false`, and `kms_key_id: null`. AWS permits any account to copy or restore a snapshot shared with `all`.
- **Why it matters:** Any AWS account can obtain and restore the snapshot's database contents, creating direct cross-account data exposure.
- **Remediation:** Immediately remove `all` from the snapshot restore attribute. Copy the snapshot with encryption enabled under an approved customer-managed KMS key, validate the encrypted copy, and delete the unencrypted original.

### 2. PostgreSQL instance is exposed to the entire Internet
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true`; security group `sg-079c850c8c2093b98` allows TCP port 5432 from `0.0.0.0/0`. Its subnet group uses subnets routed through `rtb-016da306f2c809958`, which has an active `0.0.0.0/0` route to Internet gateway `igw-0ea6103b8cbc8a1db`, and the network ACL allows all ingress and egress.
- **Why it matters:** Any Internet host can establish network connections to the PostgreSQL listener and attempt authentication or resource-exhaustion attacks.
- **Remediation:** Set `publicly_accessible` to `false`, move the instance to `brightpath-db-private`, and remove the `0.0.0.0/0` PostgreSQL ingress rule. Permit port 5432 only from specific application security groups or required private CIDRs.

### 3. Reporting database retains a public endpoint
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (DB instance, us-east-1)
- **Evidence:** The instance has `publicly_accessible: true` and uses public subnets with an Internet-gateway default route. Security group `sg-0935efccebc93d552` permits TCP port 5432 from the external CIDR `203.0.113.10/32`.
- **Why it matters:** The database listener is externally reachable from the allowed address; control of or access through that source would permit direct authentication attempts against the instance.
- **Remediation:** Set `publicly_accessible` to `false` and move the instance to `brightpath-db-private`. Provide access through private connectivity such as a VPN or Direct Connect and restrict port 5432 to a specific client security group or necessary private CIDR.

### 4. TLS is not required for private database connections
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** `brightpath-legacy-inventory-db` explicitly sets `require_secure_transport` to `0` and permits MySQL from `10.0.0.0/8`. `brightpath-orders-db-proxy` has `require_tls: false` and permits PostgreSQL client traffic from `10.81.0.0/16`.
- **Why it matters:** Clients can send database credentials, queries, and results without transport encryption. Exploitation requires access to the relevant private network path, but exposed traffic would be meaningful database data.
- **Remediation:** Set `require_secure_transport=1` for `brightpath-legacy-inventory-db` and set `require_tls=true` on `brightpath-orders-db-proxy`. Require clients to validate the RDS CA certificate and reject plaintext connections.

### 5. Proxy debug logging can place SQL details in logs
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (RDS Proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true`, which causes detailed SQL statement information to be included in its logs.
- **Why it matters:** Principals able to read the proxy logs may obtain SQL text and values or identifiers recorded with those statements, extending database information exposure to the logging plane.
- **Remediation:** Set `debug_logging=false` except during tightly controlled, time-bounded troubleshooting. Restrict access to existing logs and apply an appropriate retention period.

### 6. Two database instances are not encrypted at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Both instances have `storage_encrypted: false` and `kms_key_id: null`. Their storage and resulting native backups or snapshots therefore lack RDS storage encryption.
- **Why it matters:** This removes KMS-based protection and key-policy controls from database storage and backups; exploitation still requires access to RDS storage artifacts or control-plane permissions.
- **Remediation:** Create encrypted snapshots, copy them with encryption enabled under an approved customer-managed KMS key, and restore replacement encrypted instances. Ensure the final instances report `storage_encrypted: true`.

### 7. Deletion protection is disabled across all database instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (DB instance, us-east-1), `brightpath-billing-db` (DB instance, us-east-1), `brightpath-bi-reporting-db` (DB instance, us-east-1), `brightpath-crm-db` (DB instance, us-east-1), `brightpath-events-db` (DB instance, us-east-1), `brightpath-legacy-inventory-db` (DB instance, us-east-1), `brightpath-orders-db` (DB instance, us-east-1), `brightpath-staging-db` (DB instance, us-east-1)
- **Evidence:** Every reviewed DB instance has `deletion_protection: false`.
- **Why it matters:** A mistaken or malicious deletion request with sufficient RDS permissions can proceed without this safeguard, potentially causing service disruption and requiring recovery from retained backups.
- **Remediation:** Set `deletion_protection=true` on instances requiring continuity or retained data. Restrict `rds:ModifyDBInstance` and `rds:DeleteDBInstance` so unauthorized principals cannot disable the control and then delete an instance.
