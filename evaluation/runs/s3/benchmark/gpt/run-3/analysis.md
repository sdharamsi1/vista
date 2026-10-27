# S3 Security Review

## Account Risk Summary
The review covered 14 S3 buckets in `us-east-1`. The account has material public exposure: one bucket permits anonymous read, write, and delete operations, four permit anonymous object reads, and one exposes bucket listing through an ACL; account-level Block Public Access is not configured.

## Top Findings

### 1. Anonymous users can read, upload, overwrite, and delete partner-upload objects
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** The bucket policy allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` to `Principal: "*"` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`. AWS reports `policy_is_public: true`, while `BlockPublicPolicy` and `RestrictPublicBuckets` are both `false`.
- **Why it matters:** Any requester, including an anonymous one, can retrieve, introduce, replace, or delete objects throughout this bucket.
- **Remediation:** Remove the public allow statement. Grant only required actions to explicitly named AWS principals and constrained object prefixes, then set all four bucket Block Public Access controls to `true`.

### 2. Four buckets permit unauthenticated object downloads
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** Each bucket has `policy_is_public: true`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`. Their policies allow `s3:GetObject` to `Principal: "*"` over all customer-export objects, all website objects, the media-library `public/*` prefix, and invoice objects when `aws:Referer` matches `https://www.brightpath.example/*`; a requester can supply that Referer value.
- **Why it matters:** Unauthenticated users can retrieve objects from the policy-defined scopes. The Referer condition on the invoice bucket does not establish requester identity.
- **Remediation:** Remove the public `Principal: "*"` read grants and replace them with named principals or authenticated delivery through CloudFront Origin Access Control where internet delivery is required. Set all four bucket Block Public Access controls to `true` once anonymous access is removed.

### 3. No account-level Block Public Access guardrail is configured
- **Severity:** MEDIUM
- **Likelihood:** LOW
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-app-config-111122223333`, `brightpath-build-artifacts-111122223333`, `brightpath-customer-exports-111122223333`, `brightpath-db-backups-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-design-assets-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-s3-access-logs-111122223333`, `brightpath-shared-datasets-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is `null`, so there is no account-wide protection against public ACLs or policies. Public access is therefore controlled only by each bucket’s settings, and five buckets currently have both `BlockPublicPolicy` and `RestrictPublicBuckets` set to `false`.
- **Why it matters:** A missing account guardrail allows current or future bucket-level configuration changes to expose data publicly across the account.
- **Remediation:** Configure account-level `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` as `true`. Remove or redesign existing public bucket policies before enforcing the account-level controls.

### 4. Public ACL exposes build-artifact bucket listings
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** The bucket ACL grants `READ` to the AllUsers group `http://acs.amazonaws.com/groups/global/AllUsers`. The bucket uses `BucketOwnerPreferred`, with `BlockPublicAcls: false` and `IgnorePublicAcls: false`, so the public ACL remains effective.
- **Why it matters:** Anonymous requesters can list bucket contents and discover object names and structure, even though the bucket policy itself is not public.
- **Remediation:** Remove the AllUsers ACL grant, change object ownership to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to `true`.

### 5. Three buckets lack versioning protection against overwrite or deletion
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket reports `versioning.status: null`, with no collection errors. Unlike the other reviewed buckets, they do not retain prior versions through enabled S3 versioning.
- **Why it matters:** A principal that already has write or delete permission could overwrite or remove objects without S3 retaining a recoverable prior version.
- **Remediation:** Set bucket versioning status to `Enabled` on all three buckets and apply lifecycle rules appropriate for retaining and eventually expiring noncurrent versions.
