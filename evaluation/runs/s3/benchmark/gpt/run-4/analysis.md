# S3 Security Review

## Account Risk Summary
The review covered 14 S3 buckets in `us-east-1`. Several buckets have effective public policies or ACLs, including anonymous object deletion and object retrieval, while the account lacks an account-level Block Public Access guardrail.

## Top Findings

### 1. Anonymous users can delete objects from the partner upload bucket
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` to `Principal: "*"` across `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`. AWS reports `policy_is_public: true`, while `BlockPublicPolicy` and `RestrictPublicBuckets` are both `false`.
- **Why it matters:** An unauthenticated requester can issue deletion requests against known object keys, causing data unavailability even though versioning may permit later recovery.
- **Remediation:** Remove the wildcard-principal allow and grant only the specific partner IAM principals or roles the required actions. The resulting policy must not allow anonymous `GetObject`, `PutObject`, or `DeleteObject`, and all four bucket Block Public Access settings should be `true`.

### 2. Anonymous object retrieval is allowed by public bucket policies
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** Policies `pol-559524281564`, `pol-c8acf39b9aec`, and `pol-36c837390886` allow `s3:GetObject` to `Principal: "*"`, respectively for all invoice objects when `aws:Referer` matches `https://www.brightpath.example/*`, the media `public/*` prefix, and all website objects. Each bucket has `policy_is_public: true`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`; the `aws:Referer` request header is requester-controlled and is not authentication.
- **Why it matters:** Anyone can retrieve objects within the allowed scopes without AWS credentials; the Referer condition does not prevent a requester from directly satisfying the invoice policy.
- **Remediation:** Remove wildcard public access from invoice and media content and use authenticated principals or time-limited presigned URLs. Where public web delivery is required, restrict S3 access to a specific CloudFront service principal with an `aws:SourceArn` condition instead of direct `Principal: "*"` access.

### 3. Customer exports have a public read policy
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** PARTIAL
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`
- **Evidence:** Policy `pol-e10439958e96` allows `s3:GetObject` to `Principal: "*"` for `arn:aws:s3:::brightpath-customer-exports-111122223333/*`; AWS reports `policy_is_public: true`, and both `BlockPublicPolicy` and `RestrictPublicBuckets` are `false`. The bucket default is `sse_algorithm: "aws:kms"`, but object-level encryption and KMS authorization were not supplied.
- **Why it matters:** The policy grants public S3 authorization across every object; retrieval would succeed for objects not independently protected by KMS authorization.
- **Remediation:** Remove the wildcard `s3:GetObject` allow and grant access only to named IAM principals or through time-limited presigned URLs. Set all four bucket Block Public Access values to `true`.

### 4. No account-level Block Public Access guardrail is configured
- **Severity:** MEDIUM
- **Likelihood:** LOW
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-app-config-111122223333`, `brightpath-build-artifacts-111122223333`, `brightpath-customer-exports-111122223333`, `brightpath-db-backups-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-design-assets-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-s3-access-logs-111122223333`, `brightpath-shared-datasets-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is `null`. Consequently, the account has no centralized guardrail overriding permissive bucket policies or ACL settings.
- **Why it matters:** A bucket-level policy or ACL change can create cross-account or anonymous exposure without an account-wide control stopping it.
- **Remediation:** Configure account-level S3 Block Public Access with `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` all set to `true`, after replacing any required public delivery path with a controlled mechanism.

### 5. Versioning is not enabled on three buckets
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each affected bucket has `versioning.status: null`, while the other reviewed data buckets generally report `status: "Enabled"`.
- **Why it matters:** If a principal with write access mistakenly or maliciously overwrites or deletes an object, these buckets lack version-based recovery.
- **Remediation:** Enable S3 Versioning on all three buckets so new overwrites and deletions retain recoverable prior versions. Add lifecycle rules if storage growth must be controlled without eliminating the required recovery window.

### 6. HTTPS-only transport is not enforced on buckets without policies
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`
- **Evidence:** Both buckets have no `policy_ref`, no policy collection error, and `policy_is_public: null`, meaning no bucket policy enforces transport security. Unlike most policy-bearing buckets, neither has an explicit deny for `aws:SecureTransport: "false"`.
- **Why it matters:** A principal already authorized to access these buckets could send requests over HTTP, exposing request contents or data to interception in transit.
- **Remediation:** Add a bucket-policy statement with `Effect: "Deny"`, `Principal: "*"`, `Action: "s3:*"`, resources covering the bucket ARN and `/*`, and `Condition: {"Bool":{"aws:SecureTransport":"false"}}`.

### 7. Bucket ACL permits anonymous listing of build artifacts
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** The bucket ACL grants `READ` to the AllUsers group `http://acs.amazonaws.com/groups/global/AllUsers`. ACLs remain effective because `object_ownership` is `BucketOwnerPreferred`, while `BlockPublicAcls` and `IgnorePublicAcls` are both `false`.
- **Why it matters:** Anonymous users can list the bucket and enumerate object names and associated metadata, exposing the artifact inventory even where KMS prevents object-content retrieval.
- **Remediation:** Remove the AllUsers ACL grant, set Object Ownership to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to `true`.
