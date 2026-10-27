# S3 Security Review

## Account Risk Summary
All 14 buckets reside in us-east-1 under account 111122223333, and the account has no account-level Block Public Access configuration (`account.public_access_block` is null), so each bucket's own settings are the only gate. Five buckets return `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, including anonymous read of customer exports and anonymous write/delete on a partner upload bucket, and one bucket carries an effective AllUsers ACL.

## Top Findings

### 1. Anonymous write and delete permitted on partner upload bucket
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*` with no condition beyond the separate TLS deny; `policy_is_public` is true and the bucket has `BlockPublicPolicy: false`, `RestrictPublicBuckets: false`, with no account-level BPA to override it.
- **Why it matters:** Any anonymous requester can read, overwrite, and delete every object in the bucket, enabling data theft, tampering with content consumed by downstream workloads, and destruction of partner data (versioning is Enabled, which aids recovery but not confidentiality).
- **Remediation:** Remove the `Principal: "*"` Allow statement and grant partner access via specific IAM principals or an access point policy; set `BlockPublicPolicy` and `RestrictPublicBuckets` to true on this bucket and enable account-level Block Public Access.

### 2. Entire customer-exports bucket readable by anyone
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`
- **Evidence:** Policy `pol-e10439958e96` allows `s3:GetObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-customer-exports-111122223333/*`; AWS reports `policy_is_public: true`, and the bucket sets `BlockPublicPolicy: false` and `RestrictPublicBuckets: false` with no account-level BPA.
- **Why it matters:** Every object in an export bucket can be downloaded anonymously by anyone who knows or guesses an object key, with no requester identity recorded for authorization.
- **Remediation:** Delete the public `s3:GetObject` statement (or scope it to specific principals/VPC endpoint), and set `BlockPublicPolicy: true` and `RestrictPublicBuckets: true` on the bucket plus account-level Block Public Access.

### 3. Public AllUsers ACL effective on build artifacts bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** `acl.public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; the bucket has `BlockPublicAcls: false` and `IgnorePublicAcls: false`, `object_ownership` is `BucketOwnerPreferred` (ACLs still enforced), and there is no account-level BPA, so the grant is not ignored (`RestrictPublicBuckets` only limits public policies).
- **Why it matters:** Anonymous callers can list the bucket's object keys, exposing build artifact inventory, and `BlockPublicAcls: false` with ACLs enabled permits public object ACLs to be set on individual artifacts.
- **Remediation:** Remove the AllUsers READ grant, set `object_ownership` to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to true on this bucket.

### 4. Invoice objects publicly readable behind a spoofable Referer condition
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`
- **Evidence:** Policy `pol-559524281564` allows `s3:GetObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-invoices-111122223333/*` conditioned only on `StringLike aws:Referer = https://www.brightpath.example/*`; `policy_is_public` is true and the bucket has `BlockPublicPolicy: false`, `RestrictPublicBuckets: false`.
- **Why it matters:** The Referer header is attacker-controlled, so the condition provides no real restriction and all invoice objects are effectively anonymously readable.
- **Remediation:** Replace the Referer-based statement with a CloudFront origin-access-control (`aws:SourceArn`) or IAM-principal-scoped grant, and set `BlockPublicPolicy: true` and `RestrictPublicBuckets: true`.

### 5. No account-level Block Public Access and public-policy guards disabled on five buckets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is null, and each of these five buckets has `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`; all five already report `policy_is_public: true`.
- **Why it matters:** Nothing prevents new or widened public bucket policies on these buckets, and existing public policies are not restricted to account principals, so future misconfigurations become immediately world-reachable.
- **Remediation:** Enable account-level Block Public Access (all four flags) and set `BlockPublicPolicy: true` and `RestrictPublicBuckets: true` on every bucket, carving out intentional public delivery through CloudFront rather than public policies.

### 6. Organization-wide anonymous-principal read/write grant on shared datasets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** Policy `pol-6f84f055f825` allows `s3:GetObject` and `s3:PutObject` to `Principal: "*"` on all objects, limited only by `StringEquals aws:PrincipalOrgID = o-a1b2c3d4e5`; `policy_is_public` is false.
- **Why it matters:** Any IAM principal in any account of the organization, including low-privilege roles, can read and overwrite every object in the dataset bucket.
- **Remediation:** Replace `Principal: "*"` with the specific roles or accounts that need access and split read from write, keeping `aws:PrincipalOrgID` as an additional condition rather than the only control.

### 7. Wildcard CORS allowing cross-origin PUT and DELETE
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** CORS rule allows `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, and `AllowedHeaders: ["*"]` on a bucket that is otherwise non-public (BPA all true, policy `pol-3878b65b7e31` only denies non-TLS access).
- **Why it matters:** Any web origin can script authenticated browser requests, including object overwrite and delete, against this bucket if a user's credentials or presigned URLs are available to that page.
- **Remediation:** Restrict `AllowedOrigins` to the specific application origins and limit `AllowedMethods` to those required (typically `GET`/`HEAD`), removing `PUT` and `DELETE` unless browser upload is required.

### 8. Anonymous object read on website and media-library buckets
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-media-library-111122223333`
- **Evidence:** `pol-36c837390886` allows `s3:GetObject` to `Principal: "*"` on `brightpath-www-111122223333/*` (bucket also has static website hosting with `index.html`/`error.html`), and `pol-c8acf39b9aec` allows `s3:GetObject` to `Principal: "*"` on `brightpath-media-library-111122223333/public/*`; both report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** All objects under these paths are world-readable, so any non-public file placed in `brightpath-www-111122223333` or the `public/` prefix is immediately exposed.
- **Remediation:** Serve this content through CloudFront with origin access control and an `aws:SourceArn`-scoped policy, then enable all four Block Public Access flags; if direct public hosting is retained, ensure only publishable objects exist at those prefixes.

### 9. Versioning not enabled on three buckets
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket reports `versioning.status: null` (unset), while other buckets in the account report `Enabled`; `brightpath-db-backups-111122223333` has Object Lock Enabled but `mfa_delete: "Disabled"`.
- **Why it matters:** Without versioning, accidental or malicious overwrite and deletion of objects, including database export data, is unrecoverable.
- **Remediation:** Enable bucket versioning on all three buckets (and consider MFA delete on `brightpath-db-backups-111122223333`) so prior object versions are retained.

### 10. Server access logging missing on four buckets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-s3-access-logs-111122223333`
- **Evidence:** `logging` is null for these four buckets, whereas the other buckets log to `brightpath-s3-access-logs-111122223333` with per-bucket prefixes; `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, and `brightpath-s3-access-logs-111122223333` also use SSE-S3 (`AES256`) rather than `aws:kms`.
- **Why it matters:** Object-level access to these buckets, including the log repository itself, leaves no S3 access record, hampering detection and investigation.
- **Remediation:** Configure server access logging (or CloudTrail S3 data events) for these buckets to a dedicated log bucket with a distinct prefix, and move them to SSE-KMS where key-level control is required.
