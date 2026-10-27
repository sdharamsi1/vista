# S3 Security Review

## Account Risk Summary
Fourteen buckets were reviewed, all in us-east-1, in account 111122223333. The posture is materially weak: no account-level Block Public Access exists, five buckets carry policies AWS reports as public (`policy_is_public: true`) with bucket-level `BlockPublicPolicy`/`RestrictPublicBuckets` disabled, one bucket grants an AllUsers ACL with ACL blocking turned off, and one public policy permits anonymous object writes and deletes.

## Top Findings

### 1. Anonymous write and delete allowed on partner uploads bucket
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy pol-b9557f613e29 allows `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` with `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*` with no condition; `policy_is_public` is true and the bucket's `BlockPublicPolicy` and `RestrictPublicBuckets` are both false, with no account-level Block Public Access (`account.public_access_block: null`).
- **Why it matters:** Any anonymous internet caller can read, overwrite, and delete every object in the bucket, enabling data destruction, tampering with content consumed by downstream workloads, and use of the bucket to host arbitrary files.
- **Remediation:** Remove the `Principal: "*"` Get/Put/Delete statement (replace with specific partner principals or an access point with `aws:PrincipalOrgID`/`aws:SourceArn` conditions) and set `BlockPublicPolicy` and `RestrictPublicBuckets` to true so no public policy can take effect.

### 2. Entire object contents of customer-export and invoice buckets readable anonymously
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`
- **Evidence:** pol-e10439958e96 allows `s3:GetObject` to `Principal: "*"` on `brightpath-customer-exports-111122223333/*` unconditionally; pol-559524281564 allows `s3:GetObject` to `Principal: "*"` on `brightpath-invoices-111122223333/*` gated only by `StringLike aws:Referer https://www.brightpath.example/*`, a request header any client can set. Both report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Anyone on the internet who knows or guesses an object key can download all exported customer data and invoice objects; the Referer condition provides no real restriction.
- **Remediation:** Delete both public `s3:GetObject` statements, serve any required distribution via CloudFront with an origin access control, and enable `BlockPublicPolicy` and `RestrictPublicBuckets` on both buckets.

### 3. Public AllUsers ACL on build artifacts bucket with ACL blocking disabled
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** `acl.public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; the bucket has `BlockPublicAcls: false` and `IgnorePublicAcls: false`, `object_ownership: BucketOwnerPreferred` (ACLs still active), and no account-level Block Public Access.
- **Why it matters:** The public ACL is honored, so anonymous callers can list the bucket's object keys, revealing build artifact inventory and enabling targeted retrieval attempts; ACLs remaining enabled also allows objects to be given public ACLs.
- **Remediation:** Remove the AllUsers READ grant, set `object_ownership` to `BucketOwnerEnforced`, and enable `BlockPublicAcls` and `IgnorePublicAcls` on the bucket.

### 4. Public anonymous read on website and media buckets with public-policy blocking disabled
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-media-library-111122223333`
- **Evidence:** pol-36c837390886 allows `s3:GetObject` to `Principal: "*"` on `brightpath-www-111122223333/*` (bucket also has website hosting with `index.html`/`error.html`); pol-c8acf39b9aec allows `s3:GetObject` to `Principal: "*"` on `brightpath-media-library-111122223333/public/*`. Both report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Every object in the www bucket (not just site files) and everything under the `public/` prefix is anonymously downloadable, so any non-public object placed there is immediately exposed.
- **Remediation:** Front these buckets with CloudFront plus origin access control and remove the `Principal: "*"` statements, or at minimum narrow the www statement to the specific site prefixes; then enable `BlockPublicPolicy` and `RestrictPublicBuckets`.

### 5. No account-level Block Public Access and per-bucket blocks disabled
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`, `brightpath-build-artifacts-111122223333`
- **Evidence:** `account.public_access_block` is null, so no account-wide guardrail exists; five buckets have `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and `brightpath-build-artifacts-111122223333` has `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** With no account guardrail, any principal able to call PutBucketPolicy or PutBucketAcl can make any of the 14 buckets publicly readable or writable, and existing public policies are not restricted to in-account principals.
- **Remediation:** Enable all four Block Public Access settings at the account level and on every bucket, keeping exceptions only where a reviewed public-distribution requirement exists.

### 6. Wildcard CORS allowing PUT and DELETE from any origin
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** CORS rule has `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, `AllowedHeaders: ["*"]`; the bucket itself is not public (`policy_is_public: false`, all four BPA settings true).
- **Why it matters:** Any website can script cross-origin PUT/DELETE requests to this bucket, so a credentialed browser session or leaked presigned URL could be leveraged from an attacker-controlled page to modify or delete design assets.
- **Remediation:** Restrict `AllowedOrigins` to the specific application origins and `AllowedMethods` to those actually needed (e.g. GET), and replace `AllowedHeaders: ["*"]` with the required headers.

### 7. No versioning or server access logging on three buckets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** All three have `versioning.status: null` (never enabled) and `logging: null`, unlike the other buckets which log to `brightpath-s3-access-logs-111122223333` and have versioning Enabled.
- **Why it matters:** Objects overwritten or deleted in these buckets, including database exports, cannot be recovered and the access requests leave no S3 server access log trail for investigation.
- **Remediation:** Enable versioning on all three buckets and configure server access logging (or CloudTrail S3 data events) to `brightpath-s3-access-logs-111122223333`.

### 8. HTTPS not enforced on three buckets
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `brightpath-db-exports-111122223333` and `brightpath-media-uploads-111122223333` have no `policy_ref` and no policy collection error (no bucket policy at all); `brightpath-www-111122223333` policy pol-36c837390886 contains only the public `s3:GetObject` allow. All other buckets include a `DenyInsecureTransport` statement conditioned on `aws:SecureTransport: false`.
- **Why it matters:** Requests to these buckets may be made over plain HTTP, exposing object data and request content to network observers.
- **Remediation:** Add a `Deny` statement for `s3:*` with `Bool: {"aws:SecureTransport": "false"}` and `Principal: "*"` to each of these three bucket policies, matching the pattern already used on the other buckets.
