# S3 Security Review

## Account Risk Summary
The review covered 14 buckets in `us-east-1`. The account has several directly exploitable public-access paths, including anonymous object modification and deletion, while account-level Block Public Access is not configured.

## Top Findings

### 1. Anonymous users can read, upload, overwrite, and delete partner objects
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows Principal `*` to perform `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`. AWS reports `policy_is_public: true`, and the bucket has `BlockPublicPolicy: false` and `RestrictPublicBuckets: false`.
- **Why it matters:** Any requester can retrieve, introduce, overwrite, or destroy objects in this bucket without prior AWS access.
- **Remediation:** Remove the wildcard-principal allow statement. Grant only required actions to explicitly named partner roles or identities, optionally constrained by organization, source ARN, or VPC endpoint, and set all four bucket Block Public Access controls to `true`.

### 2. Bucket policies expose objects to anonymous requests
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** Policies `pol-e10439958e96` and `pol-36c837390886` allow Principal `*` to run `s3:GetObject` across all objects; `pol-c8acf39b9aec` does so for `public/*`. Policy `pol-559524281564` grants the same access based only on `aws:Referer` matching `https://www.brightpath.example/*`; all four buckets have `policy_is_public: true`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`.
- **Why it matters:** Objects covered by these statements can be downloaded without authenticated AWS access. The invoice policy's requester-supplied referrer condition is not an authentication control.
- **Remediation:** Remove wildcard-principal read grants and authorize specific IAM or service principals instead; use signed URLs or CloudFront origin access controls where external delivery is required. Set `BlockPublicPolicy` and `RestrictPublicBuckets` to `true` after removing public statements.

### 3. Public ACL exposes build artifacts anonymously
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** The bucket ACL grants `READ` to the AllUsers group `http://acs.amazonaws.com/groups/global/AllUsers`. ACLs remain effective because `object_ownership` is `BucketOwnerPreferred`, while `BlockPublicAcls` and `IgnorePublicAcls` are both `false`; account-level Block Public Access is absent.
- **Why it matters:** Anyone, including anonymous requesters, can exercise the bucket-level read permission granted by the ACL.
- **Remediation:** Remove the AllUsers ACL grant, change object ownership to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to `true`. The acceptable end state is an owner-only ACL with ACL-based access disabled.

### 4. Account-level Block Public Access is not configured
- **Severity:** MEDIUM
- **Likelihood:** LOW
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-app-config-111122223333`, `brightpath-build-artifacts-111122223333`, `brightpath-customer-exports-111122223333`, `brightpath-db-backups-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-design-assets-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-s3-access-logs-111122223333`, `brightpath-shared-datasets-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is `null`, so there is no account-wide Block Public Access guardrail. Public access is already effective on multiple buckets whose bucket-level `BlockPublicPolicy` and `RestrictPublicBuckets` values are `false`.
- **Why it matters:** A missing account guardrail permits current and future bucket-level ACLs or policies to create public exposure, increasing the potential blast radius across the account.
- **Remediation:** Configure account-level Block Public Access with `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` all set to `true`, after replacing any required public delivery paths with authenticated mechanisms.

### 5. Public website content is available without transport security
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-www-111122223333`
- **Evidence:** The bucket has an S3 website configuration with `index_document: index.html`, and policy `pol-36c837390886` publicly allows `s3:GetObject`. Unlike the other reviewed public-read policies, it contains no deny condition for `aws:SecureTransport: false`.
- **Why it matters:** Clients can retrieve website content over unencrypted HTTP, allowing network observers or intermediaries to observe or alter content in transit.
- **Remediation:** Serve the site through an HTTPS-enabled CloudFront distribution using origin access control. Remove direct public S3 access, enable all Block Public Access settings, and redirect HTTP clients to HTTPS at the distribution.

### 6. Versioning is not enabled on three buckets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket has `versioning.status: null`, while the other reviewed buckets report `Enabled`.
- **Why it matters:** If an identity with object modification or deletion permission acts maliciously or accidentally, overwritten and deleted objects lack S3 version-based recovery.
- **Remediation:** Enable S3 Versioning on all three buckets and add lifecycle rules appropriate for retaining and expiring noncurrent versions.
