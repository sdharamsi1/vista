# S3 Security Review

## Account Risk Summary
All 14 buckets reside in us-east-1 under account 111122223333, and the account has no account-level Block Public Access configuration (`account.public_access_block` is null), so bucket-level settings are the only control. Five buckets have policies AWS reports as public (`policy_is_public: true`) including one that grants anonymous write and delete, and one bucket is publicly readable via an AllUsers ACL that its own BPA settings do not ignore.

## Top Findings

### 1. Anonymous write and delete allowed on partner uploads bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy pol-b9557f613e29 allows `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` with `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*` with no condition, `policy_is_public` is true, and the bucket's `BlockPublicPolicy` and `RestrictPublicBuckets` are both false (account BPA is null).
- **Why it matters:** Any unauthenticated caller on the internet can read, overwrite, and delete every object in this bucket, enabling data destruction or hosting of arbitrary content under the account's bucket name.
- **Remediation:** Remove the `Principal: "*"` statement and grant partner access via specific IAM principals or an access point policy; set `BlockPublicPolicy` and `RestrictPublicBuckets` to true on the bucket and enable all four settings at the account level.

### 2. Unconditional anonymous read of all objects in customer exports bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`
- **Evidence:** Policy pol-e10439958e96 allows `s3:GetObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-customer-exports-111122223333/*`; `policy_is_public` is true and the bucket has `BlockPublicPolicy: false`, `RestrictPublicBuckets: false`.
- **Why it matters:** Every object in the bucket can be downloaded by anyone who knows or guesses an object key, with no authentication.
- **Remediation:** Delete the public `s3:GetObject` statement (keep only `DenyInsecureTransport`) and set `BlockPublicPolicy` and `RestrictPublicBuckets` to true so no public policy can take effect.

### 3. Invoices bucket publicly readable behind a forgeable Referer check
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`
- **Evidence:** Policy pol-559524281564 allows `s3:GetObject` to `Principal: "*"` on `/*` conditioned only on `StringLike aws:Referer: https://www.brightpath.example/*`; `policy_is_public` is true and `BlockPublicPolicy`/`RestrictPublicBuckets` are false.
- **Why it matters:** The Referer header is attacker-controlled, so this condition provides no access control and all invoice objects are effectively anonymously readable.
- **Remediation:** Remove the Referer-based public statement and serve content through CloudFront with an origin access control or signed URLs; set `BlockPublicPolicy` and `RestrictPublicBuckets` to true.

### 4. Public AllUsers ACL effective on build artifacts bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** `acl.public_grants` contains a READ grant to `http://acs.amazonaws.com/groups/global/AllUsers`; `object_ownership` is `BucketOwnerPreferred` (ACLs active) and the bucket sets `BlockPublicAcls: false` and `IgnorePublicAcls: false`, with no account-level BPA to override. `RestrictPublicBuckets: true` applies to public policies, not ACLs.
- **Why it matters:** Anyone on the internet can list the bucket's object keys, exposing build artifact inventory and enabling targeted retrieval attempts.
- **Remediation:** Remove the AllUsers grant, set `object_ownership` to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to true on the bucket and account.

### 5. Weakened Block Public Access on five buckets and none at the account level
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-www-111122223333`, `brightpath-build-artifacts-111122223333`
- **Evidence:** `account.public_access_block` is null; five buckets have `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`, and `brightpath-build-artifacts-111122223333` has `BlockPublicAcls: false` and `IgnorePublicAcls: false`.
- **Why it matters:** With these guardrails off, any principal able to call PutBucketPolicy or PutBucketAcl can make these buckets publicly readable or writable with no safety net.
- **Remediation:** Enable all four Block Public Access settings at the account level and on each bucket, retaining public delivery only through CloudFront or an explicitly reviewed exception.

### 6. Organization-wide anonymous-principal read/write on shared datasets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** Policy pol-6f84f055f825 allows `s3:GetObject` and `s3:PutObject` to `Principal: "*"` on `/*` conditioned only on `StringEquals aws:PrincipalOrgID: o-a1b2c3d4e5`; `policy_is_public` is false.
- **Why it matters:** Every IAM principal in any account of organization o-a1b2c3d4e5 can read and overwrite all objects, so a single compromised or over-permissioned role anywhere in the org can tamper with this data.
- **Remediation:** Replace the broad org condition with specific account/role ARNs in the `Principal` element (or add `aws:PrincipalArn` constraints) and separate read from write permissions.

### 7. Public object read on website and media-library prefixes
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-www-111122223333`, `brightpath-media-library-111122223333`
- **Evidence:** pol-36c837390886 allows `s3:GetObject` to `Principal: "*"` on `brightpath-www-111122223333/*` (bucket has website hosting with index.html/error.html); pol-c8acf39b9aec allows `s3:GetObject` to `Principal: "*"` on `brightpath-media-library-111122223333/public/*`. Both report `policy_is_public: true` with `BlockPublicPolicy: false`, `RestrictPublicBuckets: false`.
- **Why it matters:** Anything written under these paths is immediately world-readable, so a mistaken upload of non-public content is exposed without further misconfiguration.
- **Remediation:** Serve this content through CloudFront with origin access control and remove the `Principal: "*"` statements, or if direct public read must remain, confine it to a dedicated bucket/prefix with upload controls and keep all other buckets under full BPA.

### 8. Fully permissive CORS configuration allowing cross-origin writes and deletes
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-design-assets-111122223333`
- **Evidence:** CORS rule has `AllowedOrigins: ["*"]`, `AllowedMethods: ["GET","DELETE","PUT"]`, `AllowedHeaders: ["*"]`; the bucket itself is not public (all four BPA settings true, policy pol-3878b65b7e31 only denies insecure transport).
- **Why it matters:** Any web origin can script authorized browser requests, including PUT and DELETE, against this bucket if a user's credentials or presigned URLs are available to that page.
- **Remediation:** Restrict `AllowedOrigins` to the specific application domains and `AllowedMethods` to the methods actually required (typically GET/HEAD), and list only needed headers.

### 9. Buckets missing versioning, access logging, and TLS-only enforcement
- **Severity:** LOW
- **Likelihood:** LOW
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** All three have `versioning.status: null` and `logging: null`; `brightpath-db-exports-111122223333` and `brightpath-media-uploads-111122223333` have no `policy_ref` at all (no `DenyInsecureTransport` statement, unlike the other buckets) and use `AES256` without bucket keys.
- **Why it matters:** Without versioning, overwrites and deletions are unrecoverable; without access logging there is no record of requests; without a TLS-only policy, plaintext HTTP requests to these buckets are accepted.
- **Remediation:** Enable versioning and server access logging to `brightpath-s3-access-logs-111122223333`, and add a bucket policy statement denying `s3:*` when `aws:SecureTransport` is `false` on both the bucket and object ARNs.
