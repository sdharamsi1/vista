# S3 Security Review

## Account Risk Summary
14 buckets were reviewed, all in us-east-1, in account 111122223333. The account has no account-level Block Public Access configuration (`account.public_access_block` is null), and five buckets have intentionally relaxed bucket-level BPA with public bucket policies — including one bucket that grants anonymous write and delete — plus one bucket with a public AllUsers ACL grant still in effect.

## Top Findings

### 1. Anonymous read, write, and delete of all objects in brightpath-partner-uploads
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy pol-b9557f613e29 allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*` with no condition; `policy_is_public` is true and the bucket's `BlockPublicPolicy` and `RestrictPublicBuckets` are both false, with no account-level BPA to override them.
- **Why it matters:** Any unauthenticated internet user can read every object, overwrite or plant content consumed by partner workflows, and delete objects, making the bucket a vector for data theft and content tampering.
- **Remediation:** Remove the `Principal: "*"` Get/Put/Delete statement and grant partner access via specific IAM principals or an access point policy; set `BlockPublicPolicy` and `RestrictPublicBuckets` to true on the bucket and enable account-level Block Public Access.

### 2. Anonymous read of every object in brightpath-customer-exports
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`
- **Evidence:** Policy pol-e10439958e96 allows `s3:GetObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-customer-exports-111122223333/*`; `policy_is_public` is true and `BlockPublicPolicy`/`RestrictPublicBuckets` are false with no account-level BPA.
- **Why it matters:** Every object in the customer export bucket is retrievable by anyone who knows or guesses an object key, with no authentication required.
- **Remediation:** Delete the public `s3:GetObject` statement (or scope it to specific IAM/org principals) and set `BlockPublicPolicy` and `RestrictPublicBuckets` to true so no public policy can take effect.

### 3. brightpath-invoices public read gated only by a spoofable Referer header
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`
- **Evidence:** Policy pol-559524281564 allows `s3:GetObject` to `Principal: "*"` on `/*` with only `StringLike aws:Referer = https://www.brightpath.example/*`; `policy_is_public` is true and `BlockPublicPolicy`/`RestrictPublicBuckets` are false.
- **Why it matters:** The Referer header is fully attacker-controlled, so this condition provides no real restriction and all invoice objects are effectively anonymously readable.
- **Remediation:** Replace the Referer-conditioned public statement with an authenticated path (e.g. CloudFront OAC or named IAM principals) and set `BlockPublicPolicy` and `RestrictPublicBuckets` to true.

### 4. Public AllUsers ACL grant active on brightpath-build-artifacts
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** ACL `public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; `object_ownership` is `BucketOwnerPreferred` (ACLs still enforced) and the bucket's `BlockPublicAcls` and `IgnorePublicAcls` are both false, with no account-level BPA to ignore the grant.
- **Why it matters:** Anonymous users can list the bucket's object keys, exposing build artifact inventory and enabling targeted object retrieval; `RestrictPublicBuckets: true` does not affect ACL-granted access.
- **Remediation:** Remove the AllUsers READ grant, set `object_ownership` to `BucketOwnerEnforced` to disable ACLs, and set `BlockPublicAcls` and `IgnorePublicAcls` to true.

### 5. No account-level Block Public Access and BPA disabled on five buckets
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`, `brightpath-build-artifacts-111122223333`
- **Evidence:** `account.public_access_block` is null; the five policy-public buckets each have `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and `brightpath-build-artifacts-111122223333` has `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** With no account-level guardrail, any new or modified bucket policy or ACL in these buckets can make data public with nothing to reject or ignore it.
- **Remediation:** Enable all four Block Public Access settings at the account level, and keep them enabled per bucket; serve required public content through CloudFront rather than public S3 settings.

### 6. Unauthenticated object read on brightpath-www and the media-library public prefix
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-media-library-111122223333`
- **Evidence:** pol-36c837390886 allows `s3:GetObject` to `Principal: "*"` on `brightpath-www-111122223333/*` (bucket also has website hosting with index.html/error.html); pol-c8acf39b9aec allows `s3:GetObject` to `Principal: "*"` on `brightpath-media-library-111122223333/public/*`. Both report `policy_is_public: true` with `BlockPublicPolicy`/`RestrictPublicBuckets` false.
- **Why it matters:** Any object placed in these paths — including one written by mistake — is immediately world-readable with no authentication.
- **Remediation:** Front both buckets with CloudFront using an origin access control and restrict the policy to the CloudFront service principal, then enable all four BPA settings on the buckets.

### 7. Organization-wide anonymous-principal write access to brightpath-shared-datasets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** Policy pol-6f84f055f825 allows `s3:GetObject` and `s3:PutObject` to `Principal: "*"` conditioned only on `aws:PrincipalOrgID = o-a1b2c3d4e5`; `policy_is_public` is false.
- **Why it matters:** Every IAM principal in any account of the organization — not just the intended consumers — can read and overwrite dataset objects, allowing cross-account data tampering.
- **Remediation:** Replace `Principal: "*"` with the specific consuming roles/accounts, or at minimum drop `s3:PutObject` from the org-wide statement and keep write access to named principals.

### 8. Wildcard CORS allowing PUT and DELETE from any origin on brightpath-design-assets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** CORS rule has `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, and `AllowedHeaders: ["*"]`; the bucket itself is not public (`policy_is_public: false`, all BPA true).
- **Why it matters:** Any website can script cross-origin mutating requests to this bucket, which would succeed for any browser-reachable credential or presigned URL, including object deletion.
- **Remediation:** Restrict `AllowedOrigins` to the specific application origins and `AllowedMethods` to those actually required (e.g. GET), removing DELETE/PUT unless browser uploads are needed.

### 9. Versioning and server access logging missing on three buckets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** All three have `versioning.status: null` and `logging: null`, unlike the other buckets which log to `brightpath-s3-access-logs-111122223333` and have versioning Enabled; `brightpath-db-exports-111122223333` and `brightpath-media-uploads-111122223333` also use SSE-S3 (`AES256`) rather than `aws:kms`.
- **Why it matters:** Object overwrites or deletions in these buckets are unrecoverable and leave no access trail for investigation.
- **Remediation:** Enable versioning and server access logging to `brightpath-s3-access-logs-111122223333` on all three buckets, matching the baseline applied to the rest of the account.

### 10. No HTTPS-only enforcement on two buckets without bucket policies
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`
- **Evidence:** Both buckets have no `policy_ref` and no policy collection error, so they lack the `DenyInsecureTransport` statement (`Deny s3:* when aws:SecureTransport = false`) present on the other twelve buckets' policies.
- **Why it matters:** Requests to these buckets may be made over plain HTTP, exposing object data and credentials in transit.
- **Remediation:** Add a bucket policy statement denying `s3:*` on the bucket and `/*` when `aws:SecureTransport` is `false`, matching pol-ed7e8840a36d.
