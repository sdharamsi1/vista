# S3 Security Review

## Account Risk Summary
All 14 buckets in account 111122223333 reside in us-east-1, and while most are hardened (BucketOwnerEnforced, KMS, versioning, TLS-deny statements), five buckets return `policy_is_public: true` with bucket-level `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, one bucket carries an AllUsers READ ACL that is not ignored, and no account-level Block Public Access configuration exists (`account.public_access_block: null`).

## Top Findings

### 1. Anonymous read, write, and delete allowed on brightpath-partner-uploads
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*` with no condition; AWS reports `policy_is_public: true`, and the bucket's `BlockPublicPolicy: false` / `RestrictPublicBuckets: false` leave it in force (account BPA is null).
- **Why it matters:** Any unauthenticated caller on the internet can read, overwrite, and delete every object in the bucket, enabling data theft, destruction, and planting of attacker-controlled content consumed by downstream systems.
- **Remediation:** Delete the public `Allow` statement from `pol-b9557f613e29` (replace it with specific partner IAM principals or access-point-scoped grants) and set `RestrictPublicBuckets: true` and `BlockPublicPolicy: true` on the bucket, plus an account-level Block Public Access with all four flags true.

### 2. Anonymous read of all objects in customer-export and invoice buckets
- **Severity:** CRITICAL
- **Likelihood:** HIGH
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`
- **Evidence:** `pol-e10439958e96` allows `s3:GetObject` to `Principal: "*"` on `brightpath-customer-exports-111122223333/*` unconditionally; `pol-559524281564` allows the same on `brightpath-invoices-111122223333/*` gated only by `StringLike aws:Referer https://www.brightpath.example/*`, a client-supplied header. Both buckets report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Anyone who knows or guesses an object key can download every export and invoice object; the Referer condition can be set freely by the caller and provides no access control.
- **Remediation:** Remove the `Principal: "*"` `s3:GetObject` statements from both policies and serve any required public content through CloudFront with OAC or presigned URLs; then set `BlockPublicPolicy: true` and `RestrictPublicBuckets: true` on both buckets.

### 3. Public AllUsers READ ACL active on brightpath-build-artifacts
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** `acl.public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; `object_ownership` is `BucketOwnerPreferred` so ACLs are still evaluated, and the bucket sets `BlockPublicAcls: false` and `IgnorePublicAcls: false` (account BPA is null), so the grant is not ignored. `RestrictPublicBuckets: true` only limits policy-granted access, not this ACL.
- **Why it matters:** Unauthenticated callers can list the bucket's object keys, revealing build artifact names and paths that aid targeted retrieval of any objects with their own public ACLs.
- **Remediation:** Remove the AllUsers grant from the bucket ACL, set `object_ownership` to `BucketOwnerEnforced`, and set `BlockPublicAcls: true` and `IgnorePublicAcls: true` on the bucket.

### 4. Organization-wide read/write grant on brightpath-shared-datasets
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** `pol-6f84f055f825` allows `s3:GetObject` and `s3:PutObject` to `Principal: "*"` conditioned only on `StringEquals aws:PrincipalOrgID o-a1b2c3d4e5`, with no restriction on specific accounts, roles, or key prefixes (`policy_is_public: false`).
- **Why it matters:** Every IAM principal in every account of organization o-a1b2c3d4e5 can read and overwrite all objects, so a single compromised or low-privilege principal anywhere in the org gains cross-account write access to this dataset.
- **Remediation:** Replace the org-wide condition with explicit account/role ARNs in `Principal` (optionally keeping `aws:PrincipalOrgID` as an extra condition) and split read versus write grants by prefix.

### 5. Unauthenticated object read on website and media buckets
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-media-library-111122223333`
- **Evidence:** `pol-36c837390886` allows `s3:GetObject` to `Principal: "*"` on `brightpath-www-111122223333/*` (bucket also has static website hosting with `index.html`/`error.html`); `pol-c8acf39b9aec` allows `s3:GetObject` to `Principal: "*"` limited to the `public/*` prefix. Both report `policy_is_public: true` with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Any object placed in these buckets (the whole `brightpath-www` bucket, or the `public/` prefix of the media library) is readable by anyone on the internet, so a misplaced non-public object is immediately exposed.
- **Remediation:** Scope public reads to a dedicated distribution path — front the content with CloudFront using an origin access control and remove the `Principal: "*"` statements — or at minimum keep the grants strictly prefix-limited and ensure only intended public objects are written there.

### 6. Block Public Access guardrails absent at account level and weakened per bucket
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`, `brightpath-build-artifacts-111122223333`
- **Evidence:** `account.public_access_block` is `null`, so no account-wide guardrail exists; five buckets set `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and `brightpath-build-artifacts-111122223333` additionally sets `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** With no account-level backstop, any new public bucket policy or public ACL on these buckets takes effect immediately and silently, which is exactly how the existing public grants remain live.
- **Remediation:** Enable account-level Block Public Access with all four flags true and set all four flags true on each listed bucket, carving out intended public distribution via CloudFront rather than public S3 access.

### 7. Wildcard CORS allowing PUT and DELETE on brightpath-design-assets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** CORS rule sets `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, and `AllowedHeaders: ["*"]`; the bucket itself is not public (`policy_is_public: false`, all four BPA flags true).
- **Why it matters:** Any website can script authenticated browser requests (for example with presigned URLs or carried credentials) to read, overwrite, or delete objects in this bucket, and read the responses.
- **Remediation:** Restrict `AllowedOrigins` to the specific application origins, drop `DELETE`/`PUT` unless browser uploads are required, and replace `AllowedHeaders: ["*"]` with the headers actually used.

### 8. Versioning and server access logging missing on three buckets
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket reports `versioning.status: null` (never enabled) and `logging: null`, while the other buckets log to `brightpath-s3-access-logs-111122223333` and have `versioning.status: "Enabled"`.
- **Why it matters:** Object overwrites or deletions in these buckets are unrecoverable and leave no S3 access-log record, hampering both recovery and investigation.
- **Remediation:** Enable bucket versioning and server access logging (target `brightpath-s3-access-logs-111122223333` with a per-bucket prefix) on all three buckets.

### 9. No TLS-only enforcement on two buckets lacking any bucket policy
- **Severity:** LOW
- **Likelihood:** MEDIUM
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`
- **Evidence:** Neither bucket has a `policy_ref` and neither reports a policy `collection_errors` entry, so no policy exists; all other buckets carry a `DenyInsecureTransport` statement denying `s3:*` when `aws:SecureTransport` is `false`.
- **Why it matters:** Requests to these buckets sent over plain HTTP are accepted, exposing object data and credentials in transit to network observers.
- **Remediation:** Attach a bucket policy with a `Deny` on `s3:*` for `Principal: "*"` conditioned on `Bool aws:SecureTransport = false`, matching the pattern already used on the other 12 buckets.
