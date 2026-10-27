# S3 Security Review

## Account Risk Summary
All 14 buckets reside in us-east-1 under account 111122223333, and the account has no account-level Block Public Access configuration (`account.public_access_block` is null), so bucket-level settings are the only guardrail. Five buckets have public bucket policies (`policy_is_public: true`) with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and one bucket carries an AllUsers READ ACL with ACL blocking disabled — including anonymous write/delete on a partner upload bucket and anonymous read of customer exports and invoices.

## Top Findings

### 1. Anonymous read, write and delete on partner uploads bucket
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` with `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`; `policy_is_public` is true and the bucket's `BlockPublicPolicy` and `RestrictPublicBuckets` are both false, so the grant is in force.
- **Why it matters:** Any unauthenticated caller on the internet can read every object, overwrite partner-supplied data, and delete objects (versioning is Enabled, so deletes are recoverable but data can still be tampered with and the bucket used to host arbitrary content).
- **Remediation:** Remove the `Principal: "*"` Get/Put/Delete statement and scope uploads to specific partner IAM principals or roles, then set `BlockPublicPolicy` and `RestrictPublicBuckets` to true on the bucket.

### 2. Anonymous read of all objects in the customer exports bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`
- **Evidence:** Policy `pol-e10439958e96` allows `s3:GetObject` with `Principal: "*"` on `arn:aws:s3:::brightpath-customer-exports-111122223333/*`; `policy_is_public` is true with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Every object in the export bucket can be downloaded by anyone who knows or guesses a key, with no authentication required.
- **Remediation:** Delete the public `s3:GetObject` statement (or restrict it to specific principals/VPC endpoint conditions) and enable `BlockPublicPolicy` and `RestrictPublicBuckets` on the bucket.

### 3. Invoices bucket public read gated only by a spoofable Referer header
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`
- **Evidence:** Policy `pol-559524281564` allows `s3:GetObject` with `Principal: "*"` on `.../brightpath-invoices-111122223333/*` conditioned only on `StringLike aws:Referer https://www.brightpath.example/*`; `policy_is_public` is true and `BlockPublicPolicy`/`RestrictPublicBuckets` are false.
- **Why it matters:** The Referer header is fully attacker-controlled, so this is effectively unauthenticated read access to all invoice objects.
- **Remediation:** Replace the Referer condition with an authenticated access path (e.g. CloudFront origin access control with a `aws:SourceArn` condition, or specific IAM principals) and turn on `BlockPublicPolicy` and `RestrictPublicBuckets`.

### 4. Public AllUsers ACL on build artifacts bucket with ACL blocking disabled
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** `acl.public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; `object_ownership` is `BucketOwnerPreferred` (ACLs active) and `BlockPublicAcls: false`, `IgnorePublicAcls: false`, so the grant is honored and new public object ACLs can still be set.
- **Why it matters:** Anonymous callers can list the bucket contents and enumerate build artifacts, and any writer can additionally mark individual objects public-read.
- **Remediation:** Remove the AllUsers READ grant, set `object_ownership` to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to true.

### 5. Anonymous object read on the media library prefix and the website bucket
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `pol-c8acf39b9aec` allows `s3:GetObject` with `Principal: "*"` on `.../brightpath-media-library-111122223333/public/*`; `pol-36c837390886` allows `s3:GetObject` with `Principal: "*"` on `.../brightpath-www-111122223333/*`, and that bucket has website hosting configured (`index.html`/`error.html`). Both report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Anyone can read these objects; the exposure is bounded to the `public/` prefix and the static site content, but any non-public file placed under those paths becomes world-readable.
- **Remediation:** Keep the public grant only if world-readable content is required, serve it through CloudFront with origin access control instead of a public policy, and confirm no non-public keys exist under `public/` or in the website bucket.

### 6. No account-level Block Public Access and weakened bucket-level BPA
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`, `brightpath-build-artifacts-111122223333`
- **Evidence:** `account.public_access_block` is null; the five policy-public buckets each have `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and `brightpath-build-artifacts-111122223333` has `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** With no account-level backstop, any future public bucket policy or public ACL on these buckets is accepted and effective, so public exposure can be reintroduced silently.
- **Remediation:** Enable all four account-level Block Public Access settings and set all four to true on every bucket that does not require anonymous access, keeping exceptions explicit and minimal.

### 7. Organization-wide read and write grant on shared datasets bucket
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** Policy `pol-6f84f055f825` allows `s3:GetObject` and `s3:PutObject` with `Principal: "*"` conditioned on `aws:PrincipalOrgID` `o-a1b2c3d4e5`; `policy_is_public` is false and all four BPA settings are true.
- **Why it matters:** Every IAM principal in every account of the organization — not a named set of roles — can read and overwrite objects in this bucket, so a compromised principal anywhere in the org gains dataset write access.
- **Remediation:** Narrow the statement to specific account IDs or role ARNs (and read-only where write is not needed) while keeping the `aws:PrincipalOrgID` condition as an additional guard.

### 8. Wildcard CORS allowing PUT and DELETE from any origin
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** `cors` allows `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, `AllowedHeaders: ["*"]`; the bucket itself is not public (`policy_is_public: false`, all BPA true, `BucketOwnerEnforced`).
- **Why it matters:** Any web origin can script authenticated browser requests that write or delete objects, so a user's S3 credentials or presigned URLs can be abused from an attacker-controlled page.
- **Remediation:** Restrict `AllowedOrigins` to the specific application origins and drop `PUT`/`DELETE` unless browser uploads are required.

### 9. Versioning and server access logging disabled on three buckets
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each has `versioning.status: null` (never enabled); `brightpath-db-exports-111122223333` and `brightpath-media-uploads-111122223333` have `logging: null`, as does `brightpath-tmp-scratch-111122223333`, while the other buckets log to `brightpath-s3-access-logs-111122223333`.
- **Why it matters:** Object overwrites or deletions in these buckets are unrecoverable and leave no S3 access-log record for investigation.
- **Remediation:** Enable versioning and server access logging (target `brightpath-s3-access-logs-111122223333` with a per-bucket prefix) on all three buckets.

### 10. HTTPS not enforced on three buckets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`
- **Evidence:** Policy `pol-36c837390886` on `brightpath-www-111122223333` contains only the public `s3:GetObject` statement and no `aws:SecureTransport` deny, unlike the `DenyInsecureTransport` statements present on the other buckets; `brightpath-db-exports-111122223333` and `brightpath-media-uploads-111122223333` have no `policy_ref` and `policy_is_public: null`, so no bucket policy exists to enforce TLS.
- **Why it matters:** Requests to these buckets may be made over plain HTTP, exposing object data and request metadata to network observers.
- **Remediation:** Add a `Deny` statement on `s3:*` for `Principal: "*"` with condition `Bool aws:SecureTransport = false` to each bucket policy, matching the existing `DenyInsecureTransport` pattern.
