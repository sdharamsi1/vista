# RDS Security Review

## Account Risk Summary
Reviewed 8 RDS DB instances, 0 clusters, 1 RDS Proxy, and 1 manual snapshot, all in us-east-1 (account 111122223333). The posture is largely sound for the private instances, but one manual snapshot is shared publicly with all AWS accounts, one PostgreSQL instance is Internet-reachable on 5432 from 0.0.0.0/0, and TLS enforcement and at-rest encryption are missing on several resources.

## Top Findings

### 1. Manual snapshot shared with all AWS accounts
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-staging-db-pre-migration` (snapshot, us-east-1)
- **Evidence:** The manual instance snapshot of `brightpath-staging-db` has `shared_with: ["all"]` and `encrypted: false` with `kms_key_id: null`, so it is unencrypted and restorable by any AWS account.
- **Why it matters:** Any AWS principal in any account can copy and restore the snapshot and read the entire database contents offline, without reaching the VPC or authenticating to the instance.
- **Remediation:** Run `modify-db-snapshot-attribute --attribute-name restore --values-to-remove all` on `brightpath-staging-db-pre-migration` so the restore attribute lists no accounts (or only explicitly approved account IDs), and recreate it as an encrypted snapshot.

### 2. Internet-exposed PostgreSQL instance open to 0.0.0.0/0 on port 5432
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-crm-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public` (subnet-0f44bd86ce6462af4 / subnet-0fd2d728f4e981a24, route table rtb-016da306f2c809958 with a 0.0.0.0/0 route to igw-0ea6103b8cbc8a1db); security group sg-079c850c8c2093b98 allows tcp 5432 from `0.0.0.0/0` and NACL acl-0addf37833ef9393b allows all ingress and egress.
- **Why it matters:** The database endpoint is directly reachable from the entire Internet, exposing the PostgreSQL service and the `dbadmin` master login to unrestricted credential-guessing and network-level attack.
- **Remediation:** Set `publicly_accessible: false` and move the instance to the `brightpath-db-private` subnet group, and replace the 0.0.0.0/0 rule in sg-079c850c8c2093b98 with ingress from the application security group only.

### 3. Internet-facing instance in a public subnet reachable from a single external address
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected resources:** `brightpath-bi-reporting-db` (db instance, us-east-1)
- **Evidence:** `publicly_accessible: true` in subnet group `brightpath-db-public`, whose route table rtb-016da306f2c809958 routes 0.0.0.0/0 to igw-0ea6103b8cbc8a1db; sg-0935efccebc93d552 allows tcp 5432 only from `203.0.113.10/32` ("Office BI tool").
- **Why it matters:** The endpoint resolves to a public IP, so compromise or reassignment of that single allowed source address, or any loosening of the rule, immediately exposes the database to the Internet.
- **Remediation:** Set `publicly_accessible: false` and place the instance in `brightpath-db-private`, reaching it from the office network over VPN/Direct Connect or a bastion instead of an Internet-routable endpoint.

### 4. TLS not enforced on two databases and the RDS Proxy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-billing-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** Parameter group `brightpath-billing-db` sets `rds.force_ssl=0`, parameter group `brightpath-legacy-inventory-db` sets `require_secure_transport=0`, and the proxy has `require_tls: false`; all three are explicit user modifications permitting plaintext client connections.
- **Why it matters:** Clients may connect without TLS, so credentials and query data can be read or modified by anything able to observe traffic inside vpc-0de19d260a9ad9f27.
- **Remediation:** Set `rds.force_ssl=1` on `brightpath-billing-db`, `require_secure_transport=1` on `brightpath-legacy-inventory-db`, and `require_tls: true` on `brightpath-orders-db-proxy` so only TLS connections are accepted.

### 5. Legacy MySQL instance relies on an unmanaged static password with broad internal reachability
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-legacy-inventory-db` (db instance, us-east-1)
- **Evidence:** `iam_auth_enabled: false` and `master_user_secret: null` (master password not managed or rotated in Secrets Manager), `log_exports: []`, `backup_retention_days: 1`, and sg-0c297cdba6b8b1a6b allows tcp 3306 from the whole `10.0.0.0/8` range — unlike the other instances, which use IAM auth and RDS-managed secrets.
- **Why it matters:** A static, unrotated `dbadmin` password reachable from a very broad internal CIDR, with no exported logs and a single day of backups, makes misuse of this database hard to detect and recover from.
- **Remediation:** Enable IAM database authentication and RDS-managed master password rotation, narrow sg-0c297cdba6b8b1a6b ingress to the specific application security group, enable `error`/`general`/`audit` log exports, and raise backup retention to at least 7 days.

### 6. Databases stored without encryption at rest
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** Both instances report `storage_encrypted: false` and `kms_key_id: null`, while the other six instances are encrypted with customer-managed key a343a413-1375-4d20-b1e5-78c139bf45a2 (key_state Enabled).
- **Why it matters:** Volumes, automated backups, and snapshots of these instances carry no KMS protection, so data is readable wherever the storage or a copied snapshot is accessible without a key-policy check.
- **Remediation:** Recreate these instances from encrypted snapshot copies using the existing customer-managed KMS key so `storage_encrypted` is true for every instance.

### 7. RDS Proxy logs detailed SQL and has IAM authentication disabled
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-orders-db-proxy` (db proxy, us-east-1)
- **Evidence:** The proxy has `debug_logging: true`, and its single auth entry uses `auth_scheme: SECRETS` with `iam_auth: DISABLED` (secret rds!db-0bd5ab11… for `brightpath-orders-db`); `default_auth_scheme` is NONE.
- **Why it matters:** Debug logging writes SQL statement detail, which can include data values, into logs readable by anyone with log read permission, and without IAM auth proxy access depends solely on database credentials.
- **Remediation:** Set `debug_logging: false` on `brightpath-orders-db-proxy` (enable only transiently for troubleshooting) and set `iam_auth: REQUIRED` for its auth entry.

### 8. Deletion protection disabled on all DB instances
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected resources:** `brightpath-analytics-db` (db instance, us-east-1), `brightpath-billing-db` (db instance, us-east-1), `brightpath-bi-reporting-db` (db instance, us-east-1), `brightpath-crm-db` (db instance, us-east-1), `brightpath-events-db` (db instance, us-east-1), `brightpath-legacy-inventory-db` (db instance, us-east-1), `brightpath-orders-db` (db instance, us-east-1), `brightpath-staging-db` (db instance, us-east-1)
- **Evidence:** All eight instances report `deletion_protection: false`, and every instance also has `monitoring_interval_seconds: 0` (enhanced monitoring off).
- **Why it matters:** A compromised or mistaken API caller holding rds:DeleteDBInstance can destroy any of these databases with no API-level guard in place.
- **Remediation:** Set `deletion_protection: true` on these instances and restrict `rds:DeleteDBInstance` to a break-glass role via IAM policy or an SCP.
