# S3 Security Review

## Account Risk Summary
The account has substantial S3 exposure: 14 buckets were reviewed in `us-east-1`, including one anonymously writable/deletable bucket and five buckets with public access paths. Account-level Block Public Access is not configured.

## Top Findings

### 1. Anonymous users can read, write, and delete partner-upload objects
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows Principal `*` to perform `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`. AWS reports `policy_is_public: true`, while `BlockPublicPolicy` and `RestrictPublicBuckets` are both `false`.
- **Why it matters:** Any unauthenticated requester can upload arbitrary objects and can read or delete objects when their keys are known, enabling cross-account data access, tampering, and destruction.
- **Remediation:** Remove the anonymous Allow statement and grant only the required object actions to explicitly named partner IAM principals or roles. Set `BlockPublicPolicy` and `RestrictPublicBuckets` to `true`, with the resulting policy status no longer public.

### 2. Anonymous policies expose objects from four buckets
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** Each bucket has `policy_is_public: true` and both `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`. Their policies allow Principal `*` to use `s3:GetObject`: all objects in `brightpath-customer-exports-111122223333` and `brightpath-www-111122223333`, all objects in `brightpath-invoices-111122223333` when `aws:Referer` matches `https://www.brightpath.example/*`, and `public/*` in `brightpath-media-library-111122223333`.
- **Why it matters:** Unauthenticated requesters can download existing objects covered by these resource patterns. The invoice policy's `aws:Referer` value is requester-supplied and does not provide reliable authentication.
- **Remediation:** Remove the Principal `*` GetObject statements, including the Referer-based statement, and grant access only to named IAM or service principals or through authenticated signed access. Set `BlockPublicPolicy` and `RestrictPublicBuckets` to `true` so each bucket reaches `policy_is_public: false`.

### 3. Public bucket ACL permits anonymous artifact enumeration
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** The bucket ACL grants `READ` to the AllUsers group `http://acs.amazonaws.com/groups/global/AllUsers`. ACLs remain effective because object ownership is `BucketOwnerPreferred`, while `BlockPublicAcls` and `IgnorePublicAcls` are both `false`.
- **Why it matters:** Anonymous users can list bucket contents and expose artifact names and related object metadata, even though the supplied bucket policy is not public.
- **Remediation:** Remove the AllUsers ACL grant, set object ownership to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to `true`. The end state should contain no public ACL grants.

### 4. Account-level Block Public Access guardrail is absent
- **Severity:** MEDIUM
- **Likelihood:** LOW
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-app-config-111122223333`, `brightpath-build-artifacts-111122223333`, `brightpath-customer-exports-111122223333`, `brightpath-db-backups-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-design-assets-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-s3-access-logs-111122223333`, `brightpath-shared-datasets-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is `null`, so the account supplies no centralized Block Public Access protection. Several buckets currently have bucket-level `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and one also has `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** A bucket-level policy or ACL change can create public exposure without an account-wide backstop, potentially affecting any S3 data in the account.
- **Remediation:** Configure account-level Block Public Access with `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` all set to `true`. Keep equivalent bucket-level settings enabled for defense in depth.

### 5. Three buckets lack versioning protection
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket has `versioning.status: null` and `object_lock: null`. Unlike the other reviewed buckets, they retain no supplied version history or immutable recovery control.
- **Why it matters:** A principal that already has overwrite or delete permission could permanently destroy or replace objects without recoverable prior versions.
- **Remediation:** Enable S3 Versioning on all three buckets so `versioning.status` becomes `Enabled`. Apply appropriately scoped retention controls where protection against deletion of versions is required.
