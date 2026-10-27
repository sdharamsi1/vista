# S3 Security Review

## Account Risk Summary
The account has several direct public-access paths and one broadly scoped organization-wide data-sharing policy. Fourteen buckets were reviewed, all in `us-east-1`.

## Top Findings

### 1. Anonymous users can modify and delete partner-upload objects
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-partner-uploads-111122223333`
- **Evidence:** Policy `pol-b9557f613e29` allows Principal `"*"` to perform `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on `arn:aws:s3:::brightpath-partner-uploads-111122223333/*`. AWS reports `policy_is_public: true`, while `BlockPublicPolicy` and `RestrictPublicBuckets` are both `false`.
- **Why it matters:** Any unauthenticated requester can attempt to upload, replace, retrieve, or delete objects, creating direct integrity, availability, and data-exposure risks within this bucket.
- **Remediation:** Remove the public allow statement and grant only required actions to explicit partner role ARNs or a narrowly controlled upload mechanism. Set all four bucket Block Public Access settings to `true`.

### 2. Any principal in the AWS Organization receives object read and write access
- **Severity:** HIGH
- **Likelihood:** MEDIUM
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-shared-datasets-111122223333`
- **Evidence:** Policy `pol-6f84f055f825` grants Principal `"*"` both `s3:GetObject` and `s3:PutObject` on `arn:aws:s3:::brightpath-shared-datasets-111122223333/*` when `aws:PrincipalOrgID` equals `o-a1b2c3d4e5`. This encompasses qualifying principals across every account in that organization rather than named workloads.
- **Why it matters:** A principal already present in any qualifying organization account can read or write shared dataset objects, enabling cross-account and cross-workload data access.
- **Remediation:** Replace Principal `"*"` plus the organization-wide condition with explicit trusted role ARNs. Limit each role to required actions and object prefixes, with the end state permitting only identified workloads.

### 3. Unconditional public policies expose objects for anonymous download
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-customer-exports-111122223333`, `brightpath-media-library-111122223333`, `brightpath-www-111122223333`
- **Evidence:** Policies `pol-e10439958e96`, `pol-c8acf39b9aec`, and `pol-36c837390886` grant Principal `"*"` `s3:GetObject` on all customer-export objects, the `public/*` media prefix, and all website objects, respectively. Each bucket has `policy_is_public: true`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`.
- **Why it matters:** Objects matching these resources have public S3 read authorization; objects requiring no separate KMS authorization can be downloaded without AWS credentials.
- **Remediation:** Remove the Principal `"*"` allows and grant reads to explicit IAM or service principals, scoped to necessary prefixes. Set all four bucket Block Public Access settings to `true` once anonymous access has been removed.

### 4. Spoofable Referer condition provides public access to invoice objects
- **Severity:** HIGH
- **Likelihood:** HIGH
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-invoices-111122223333`
- **Evidence:** Policy `pol-559524281564` grants Principal `"*"` `s3:GetObject` on every object when `aws:Referer` matches `https://www.brightpath.example/*`. The bucket has `policy_is_public: true`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`.
- **Why it matters:** The HTTP Referer header is requester-controlled and does not authenticate a caller, so an unauthenticated requester can satisfy this condition and retrieve matching objects.
- **Remediation:** Remove the Referer-based public allow and use authenticated access through explicit IAM principals or time-limited presigned URLs. Set `BlockPublicPolicy` and `RestrictPublicBuckets` to `true`.

### 5. Public bucket ACL exposes build-artifact object listings
- **Severity:** MEDIUM
- **Likelihood:** HIGH
- **Impact:** LOW
- **Confidence:** CONFIRMED
- **Category:** PUBLIC_EXPOSURE
- **Affected buckets:** `brightpath-build-artifacts-111122223333`
- **Evidence:** The bucket ACL grants the AllUsers group `READ`, and `public_grants` contains that grant. `IgnorePublicAcls` and `BlockPublicAcls` are both `false`, and object ownership is `BucketOwnerPreferred`, so the bucket ACL remains effective.
- **Why it matters:** Anonymous users can list bucket contents and obtain build-artifact names and related object metadata, although the supplied bucket ACL alone does not grant object downloads.
- **Remediation:** Remove the AllUsers ACL grant, set object ownership to `BucketOwnerEnforced`, and set `BlockPublicAcls` and `IgnorePublicAcls` to `true`.

### 6. Versioning is disabled on buckets vulnerable to unrecoverable overwrite or deletion
- **Severity:** MEDIUM
- **Likelihood:** MEDIUM
- **Impact:** MEDIUM
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-db-exports-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-tmp-scratch-111122223333`
- **Evidence:** Each bucket reports `versioning.status: null`, while the other reviewed buckets report `Enabled`. No object lock is configured on these three buckets.
- **Why it matters:** A principal that obtains or already has write or delete permission can overwrite or remove current objects without retained prior versions for bucket-level recovery.
- **Remediation:** Enable S3 Versioning on each bucket so the status is `Enabled`. Add lifecycle rules for noncurrent versions if retention cost must be bounded.

### 7. No account-level Block Public Access guardrail is configured
- **Severity:** MEDIUM
- **Likelihood:** LOW
- **Impact:** HIGH
- **Confidence:** CONFIRMED
- **Category:** SECURITY_CONFIGURATION
- **Affected buckets:** `brightpath-app-config-111122223333`, `brightpath-build-artifacts-111122223333`, `brightpath-customer-exports-111122223333`, `brightpath-db-backups-111122223333`, `brightpath-db-exports-111122223333`, `brightpath-design-assets-111122223333`, `brightpath-invoices-111122223333`, `brightpath-media-library-111122223333`, `brightpath-media-uploads-111122223333`, `brightpath-partner-uploads-111122223333`, `brightpath-s3-access-logs-111122223333`, `brightpath-shared-datasets-111122223333`, `brightpath-tmp-scratch-111122223333`, `brightpath-www-111122223333`
- **Evidence:** `account.public_access_block` is `null`, so there is no account-wide Block Public Access configuration. Consequently, bucket-level settings with `BlockPublicPolicy: false` and `RestrictPublicBuckets: false` are not overridden by a stricter account control.
- **Why it matters:** A bucket-level ACL or policy mistake can create cross-account or public exposure without an account-wide preventive guardrail.
- **Remediation:** Configure account-level Block Public Access with `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` all set to `true`, after removing any public-access dependencies.
