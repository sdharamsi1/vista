# Test scenarios and ground truth

This folder deploys 40 deliberately built AWS scenarios with Terraform and records the correct answer for each one. They are the answer key for evaluating how well Vista's LLM review rates real exposure, tells expected configurations from risks, and routes uncertain cases to a person.

Each module under `modules/` (`ec2`, `s3`, `apigateway`, `rds`) creates its scenarios and has a `ground-truth.json` that holds the expected result for every scenario. This README restates that file in prose. If the two differ, `ground-truth.json` is the source of truth. The `scenario_resources` Terraform output maps each scenario ID to the resource identifier Vista cites, which is how a finding is matched to a scenario.

## How the scenarios are organized

Every scenario belongs to one of two tiers:

- **controlled:** A ladder of single flaws, from a low-impact misconfiguration up to a critical one, so severity ratings can be compared like for like.
- **realistic:** Messier setups that share infrastructure such as a load balancer, a NAT gateway, and data stores. They include safe-looking resources that are risky, risky-looking resources that are safe, and cases that depend on intent.

Every scenario also has one of four kinds:

- **dangerous (26):** A real weakness Vista must report within the acceptable severity range, and a person should fix it (REMEDIATE).
- **ambiguous (7):** Defensible either way. The model should explain the tradeoff or defer to a person (REVIEW). Reporting nothing and over-rating are both wrong.
- **expected (6):** A correctly configured resource, or an exposure that another control blocks. The right result is no finding or a LOW hygiene note (NO_ACTION).
- **minor (1):** A small, real gap. The right result is LOW or no finding (REMEDIATE).

Scenarios per module: EC2 11, S3 11, API Gateway 9, RDS 9.

## How to read the expected values

- **Category** is the kind of problem: `INTERNET_EXPOSURE`, `PUBLIC_EXPOSURE`, `ACCESS_CONTROL`, or `SECURITY_CONFIGURATION`.
- **Likelihood** follows CCSS (NIST IR 7502) exploitability, aligned with Vista's definitions. HIGH means reachable from the Internet and usable without credentials. MEDIUM means one precondition must hold first, such as a credential or API key, a foothold inside the network, an application flaw, or compromise of the resource. LOW means prior account-level access is needed or the issue is defense in depth only.
- **Impact** follows CCSS confidentiality, integrity, and availability impact, widened by the outcome of the mapped ATT&CK technique. HIGH means account-wide reach, privilege escalation, or full read, write, and delete of data. MEDIUM means confined to the resource or one data store. LOW means minor or visibility-only impact.
- **Severity** comes from Vista's likelihood by impact matrix.
- **Acceptable severities** are the expected severity plus one adjacent level. The extra level goes toward the AWS Security Hub FSBP reference severity when one exists, otherwise toward the axis the rationale marks as uncertain. Expected scenarios accept NONE and LOW. Ambiguous scenarios accept one level on each side, and a deferral counts as appropriate.
- **Expected action** is what a person should do: REMEDIATE for dangerous and minor scenarios, REVIEW for ambiguous ones, NO_ACTION for expected ones. It comes from the kind and is not rated separately. **Acceptable actions** lists every action that counts as a tolerant match. Reports give both the strict result (expected action) and the tolerant result (acceptable actions).
- **Frameworks** show where each scenario is anchored: AWS Security Hub Foundational Security Best Practices (FSBP) controls and their published severities, MITRE ATT&CK techniques, the OWASP API Security Top 10 (API Gateway), and CCSS for the likelihood and impact rules. Controls that fail on every resource in a module are listed in `baseline_controls` in the JSON and are left out of the per-scenario references. A context override means documented context removes the attack path FSBP assumes.

A scenario passes when the highest-severity finding that cites its resource, or NONE if no finding cites it, is in the acceptable severities and, if cited, has an expected or acceptable category. `scripts/score.py` applies these rules.

## Revisions made after the pilot

Two changes were made after seeing pilot output and before the benchmark runs. Each is logged in the `change_log` of the affected JSON file.

- `ec2-06` was reclassified from expected to ambiguous. Both evaluated models and Prowler reported the load balancer path, and Vista's guidance requires a confirmed public path to be at least MEDIUM likelihood.
- `acceptable_actions` was added to every scenario. The `ec2-02` rule that also accepts REVIEW is the one rule fitted to model outputs.

The framework-anchored severity ranges were set before any model run.

## EC2 scenarios

### ec2-01: Private instance with an unencrypted root volume

- **Resource:** `reporting-worker`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private reporting worker with no inbound security-group rules and no IAM role.
- **What is wrong:** The root volume is unencrypted. Reading it requires prior account access, so this is a defense-in-depth gap, not an exposure.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP EC2.3 (reference severity MEDIUM); ATT&CK T1578.001

### ec2-02: Public instance with HTTP and HTTPS open to 0.0.0.0/0

- **Resource:** `marketing-site`
- **Tier and kind:** controlled, dangerous
- **What it is:** A marketing site on an instance with a public IP.
- **What is wrong:** Ports 80 and 443 are open to 0.0.0.0/0, which is a confirmed direct Internet path. They are ordinary web ports, IMDSv2 is enforced, and no role is attached, so the blast radius is the instance itself. Whether public hosting is intended cannot be seen in the data, so REVIEW is accepted along with REMEDIATE.
- **Expected rating:** category INTERNET_EXPOSURE, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE, REVIEW)
- **Frameworks:** FSBP EC2.9 (reference severity HIGH); ATT&CK T1190
- **Note:** EC2.18 passes because 80 and 443 are its default authorized ports.

### ec2-03: Private instance with IMDSv1 and a role that reads the uploads bucket

- **Resource:** `image-resizer`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private image-resizer instance whose role can read the uploads bucket.
- **What is wrong:** IMDSv1 is enabled, so an SSRF or local foothold could steal the role credentials. The instance is private and the role is limited to one bucket.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP EC2.8 (reference severity HIGH); ATT&CK T1552.005

### ec2-04: Private CI runner whose role can attach any policy to any role

- **Resource:** `ci-runner`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private CI runner.
- **What is wrong:** Its role can attach any policy to any role (iam:AttachRolePolicy and iam:PutRolePolicy on *), so it can grant itself AdministratorAccess. Exploiting this requires the instance to be compromised first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact HIGH, severity HIGH
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1098.003, T1078.004
- **Note:** No FSBP control applies: IAM.1 evaluates customer-managed policies that grant *:*.

### ec2-05: Legacy bastion with SSH open to 0.0.0.0/0 and an AdministratorAccess role

- **Resource:** `legacy-bastion`
- **Tier and kind:** controlled, dangerous
- **What it is:** A legacy bastion in the legacy VPC with an AdministratorAccess role.
- **What is wrong:** SSH is open to 0.0.0.0/0 over a confirmed direct path, and compromise yields full account control. The rule description calls the rule temporary, which does not reduce the risk.
- **Expected rating:** category INTERNET_EXPOSURE, likelihood HIGH, impact HIGH, severity CRITICAL
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP EC2.19, EC2.13, EC2.53, EC2.9 (reference severity CRITICAL); ATT&CK T1110, T1021.004, T1078.004

### ec2-06: Storefront behind an internet-facing HTTPS load balancer

- **Resource:** `storefront-web`
- **Tier and kind:** realistic, ambiguous
- **What it is:** A storefront web instance behind an internet-facing HTTPS load balancer. It has no public IP, port 8080 accepts traffic only from the load balancer's security group, the load balancer terminates TLS 1.2+ and redirects HTTP, and IMDSv2 and encryption are on.
- **What is wrong:** This looks like a normal public web tier, but there is still a confirmed public path, the load balancer has no WAF or access logs, and whether the exposure is intended depends on approved intent that is not supplied. REVIEW at LOW is the expected answer; NO_ACTION or MEDIUM is also defensible.
- **Expected rating:** category INTERNET_EXPOSURE, likelihood MEDIUM, impact LOW, severity LOW
- **Acceptable severities:** NONE, LOW, MEDIUM
- **Expected action:** REVIEW (acceptable: REVIEW, NO_ACTION)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP ELB.5, ELB.16 (reference severity MEDIUM)
- **Note:** The instance itself passes EC2.3, EC2.8, and EC2.9; ELB.5 and ELB.16 apply to the ALB in front of it.

### ec2-07: Internet-reachable orders API with IMDSv1 and a role that reads every secret

- **Resource:** `orders-api`
- **Tier and kind:** realistic, dangerous
- **What it is:** An orders API instance with no public IP, behind the internet-facing load balancer, which forwards /api/* to it.
- **What is wrong:** IMDSv1 is on and the role has secretsmanager:GetSecretValue on *. An SSRF in the application would expose credentials that reach every workload's secrets. It needs an application flaw first, so likelihood is MEDIUM. The scenario tests whether the model follows the load balancer path and chains it with IMDS and IAM.
- **Expected rating:** category INTERNET_EXPOSURE, likelihood MEDIUM, impact HIGH, severity HIGH
- **Acceptable severities:** MEDIUM, HIGH
- **Acceptable categories:** INTERNET_EXPOSURE, SECURITY_CONFIGURATION
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP EC2.8, ELB.16 (reference severity HIGH); ATT&CK T1190, T1552.005, T1555.006

### ec2-08: Public bastion with SSH limited to the office network

- **Resource:** `admin-bastion`
- **Tier and kind:** realistic, ambiguous
- **What it is:** An admin bastion with a public IP. SSH is allowed only from the office /24, the role is the SSM core policy, and there is no key pair.
- **What is wrong:** A narrow, documented source is a common accepted pattern. Suggesting SSM Session Manager instead is reasonable, but rating it HIGH or CRITICAL is over-rating.
- **Expected rating:** category INTERNET_EXPOSURE, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** NONE, LOW, MEDIUM
- **Expected action:** REVIEW (acceptable: REVIEW, NO_ACTION)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP EC2.9 (reference severity HIGH); ATT&CK T1021.004
- **Context override:** SSH is allowed only from the office /24, so EC2.13, EC2.19, and EC2.53 pass and the public IP alone does not give an Internet path to SSH.

### ec2-09: Security group opens 9100 to the world, but the subnet's network ACL denies it

- **Resource:** `metrics-collector`
- **Tier and kind:** realistic, expected
- **What it is:** A metrics collector with a public IP whose security group allows port 9100 from 0.0.0.0/0.
- **What is wrong:** The ops subnet's network ACL denies TCP 9100 inbound at rule 90, before rule 100 allows everything else, so there is no Internet path. A model that rates this MEDIUM or above ignored the network ACL. A LOW note about the broad security group is fine.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** FSBP EC2.9, EC2.18 (reference severity HIGH)
- **Context override:** The ops subnet's network ACL denies TCP 9100 inbound, so the security group rule FSBP flags is not reachable from the Internet.

### ec2-10: Private notebook open to 10.0.0.0/8 with s3:* on every bucket

- **Resource:** `analytics-notebook`
- **Tier and kind:** realistic, dangerous
- **What it is:** A private analytics notebook running Jupyter on port 8888.
- **What is wrong:** The port is open to all of 10.0.0.0/8, far wider than the VPC, and the role can read, write, and delete every bucket in the account. It is not Internet-reachable, so it needs an internal foothold first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact HIGH, severity HIGH
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1530, T1485
- **Note:** No FSBP control applies: EC2.19 checks 0.0.0.0/0 only, and IAM.21 skips inline policies.

### ec2-11: Private queue worker scoped to one SQS queue

- **Resource:** `queue-worker`
- **Tier and kind:** realistic, expected
- **What it is:** A private queue worker with no public IP, only the VPC-internal monitoring security group, IMDSv2, encryption, and a role limited to receive and delete on one queue plus the SSM core policy.
- **What is wrong:** Nothing. It is correctly configured and should produce no finding.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** none apply

## S3 scenarios

### s3-01: CORS allows any origin to send GET, PUT, and DELETE

- **Resource:** `design-assets`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private, TLS-only design-assets bucket.
- **What is wrong:** The CORS configuration allows any origin to send GET, PUT, and DELETE. CORS grants no access on its own, so it only matters if a caller already has credentials or a presigned URL.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** none apply
- **Note:** No FSBP control covers CORS.

### s3-02: public-read ACL lets anyone list object names

- **Resource:** `build-artifacts`
- **Tier and kind:** controlled, dangerous
- **What it is:** A build-artifacts bucket.
- **What is wrong:** A public-read ACL grants AllUsers READ on the bucket, so anyone can list object names. The grant survives Block Public Access and BucketOwnerPreferred ownership. Object contents stay private, so the expected severity is MEDIUM even though FSBP rates the public grant Critical.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact LOW, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP S3.2, S3.8, S3.12 (reference severity CRITICAL); ATT&CK T1619
- **Context override:** The public grant allows listing object names only; object contents stay private.

### s3-03: Wildcard principal can read and write objects from any account in the organization

- **Resource:** `shared-datasets`
- **Tier and kind:** controlled, dangerous
- **What it is:** A shared-datasets bucket whose policy uses a wildcard principal limited by aws:PrincipalOrgID.
- **What is wrong:** It is not public, but any principal in any account in the organization can read and overwrite objects. Exploiting it needs an organization foothold first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1530, T1565.001
- **Note:** S3.6 does not fail: its fixed denylist covers policy- and ACL-changing actions, not GetObject or PutObject.

### s3-04: Bucket policy allows anonymous s3:GetObject

- **Resource:** `customer-exports`
- **Tier and kind:** controlled, dangerous
- **What it is:** A customer-exports bucket.
- **What is wrong:** The bucket policy allows s3:GetObject to Principal * with no condition, and the Block Public Access policy flags are off, so every object is readable by anyone on the Internet.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact MEDIUM, severity HIGH
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP S3.2, S3.8 (reference severity CRITICAL); ATT&CK T1530

### s3-05: Bucket policy allows anonymous read, write, and delete

- **Resource:** `partner-uploads`
- **Tier and kind:** controlled, dangerous
- **What it is:** A partner-uploads bucket.
- **What is wrong:** The bucket policy allows anonymous read, write, and delete. Anyone can steal, overwrite, or destroy objects and host malware without credentials.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact HIGH, severity CRITICAL
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP S3.2, S3.3, S3.8 (reference severity CRITICAL); ATT&CK T1530, T1565.001, T1485

### s3-06: Static website bucket with anonymous read

- **Resource:** `www`
- **Tier and kind:** realistic, ambiguous
- **What it is:** A static website bucket named www, with website hosting enabled and anonymous read.
- **What is wrong:** Anonymous GetObject is the purpose of the bucket, and website endpoints require SSE-S3 and no TLS-only rule. Without account intent the model cannot confirm the content is meant to be public, so MEDIUM or HIGH with that caveat, or a deferral, is correct. CRITICAL treats a website as a data leak.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact LOW, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM, HIGH
- **Expected action:** REVIEW (acceptable: REVIEW)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP S3.2, S3.8, S3.5, S3.17 (reference severity CRITICAL); ATT&CK T1530
- **Context override:** Static website hosting is enabled and anonymous read is its purpose; S3 website endpoints require HTTP and SSE-S3.

### s3-07: Anonymous read limited to the public/ prefix

- **Resource:** `media-library`
- **Tier and kind:** realistic, ambiguous
- **What it is:** A media-library bucket where only objects under the public/ prefix are anonymously readable and the rest is private.
- **What is wrong:** Whether this is a leak depends on what is stored under public/, which the data does not show. The model should name the prefix scope and ask for confirmation instead of calling the whole bucket public.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact LOW, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM, HIGH
- **Expected action:** REVIEW (acceptable: REVIEW)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP S3.2, S3.8, S3.17 (reference severity CRITICAL); ATT&CK T1530
- **Context override:** Only objects under public/ are anonymously readable.

### s3-08: Anonymous read restricted only by aws:Referer

- **Resource:** `invoices`
- **Tier and kind:** realistic, dangerous
- **What it is:** An invoices bucket whose policy allows anonymous read only when the aws:Referer header matches.
- **What is wrong:** The Referer header is set by the client, so anyone can send it. The policy is effectively anonymous read of every object, and AWS reports the bucket as public. The scenario tests whether the model treats a spoofable condition as a real restriction.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact MEDIUM, severity HIGH
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP S3.2, S3.8, S3.17 (reference severity CRITICAL); ATT&CK T1530

### s3-09: Fully hardened application configuration bucket

- **Resource:** `app-config`
- **Tier and kind:** realistic, expected
- **What it is:** A fully hardened application configuration bucket: Block Public Access on, ACLs disabled, SSE-KMS, versioning, access logging, and TLS-only.
- **What is wrong:** Nothing. It should produce no finding.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** none apply

### s3-10: Fully hardened backup bucket with Object Lock

- **Resource:** `db-backups`
- **Tier and kind:** realistic, expected
- **What it is:** A fully hardened backup bucket, the same as app-config plus Object Lock.
- **What is wrong:** Nothing. A note that no default retention is set is reasonable but no more than LOW.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** none apply

### s3-11: Private scratch bucket without versioning or access logging

- **Resource:** `tmp-scratch`
- **Tier and kind:** realistic, minor
- **What it is:** A private, encrypted, TLS-only scratch bucket.
- **What is wrong:** Versioning and access logging are missing. This only reduces recoverability and visibility. FSBP rates missing server access logging (S3.9) Medium, so MEDIUM is also accepted.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood LOW, impact LOW, severity LOW
- **Acceptable severities:** NONE, LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE, NO_ACTION)
- **Frameworks:** FSBP S3.9, S3.14 (reference severity MEDIUM)

## API Gateway scenarios

### apigw-01: IAM-authenticated API with no access logging

- **Resource:** `inventory-api`
- **Tier and kind:** controlled, dangerous
- **What it is:** An inventory API where every route requires IAM authorization, WAF and throttling are on, and execution logging is on.
- **What is wrong:** Access logging is missing, which only costs visibility into who called the API.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood LOW, impact LOW, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** OWASP API API8:2023
- **Note:** APIGateway.9 covers HTTP and WebSocket stages only; APIGateway.1 (execution logging) passes.

### apigw-02: Execution logging records full request and response bodies

- **Resource:** `support-tickets-api`
- **Tier and kind:** controlled, dangerous
- **What it is:** A support-tickets API.
- **What is wrong:** dataTraceEnabled on */* writes every Scan result and request body to CloudWatch Logs, where anyone who can read the log group sees stored data. Reading the logs needs account access first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** OWASP API API8:2023
- **Note:** APIGateway.1 passes; no FSBP control covers dataTraceEnabled.

### apigw-03: IAM-authenticated API with no WAF and no throttling

- **Resource:** `reporting-api`
- **Tier and kind:** controlled, dangerous
- **What it is:** A reporting API with IAM authorization on every route.
- **What is wrong:** There is no web ACL and no stage throttle, so only the account-level limit applies and one client can consume regional capacity. Callers are still authenticated.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP APIGateway.4 (reference severity MEDIUM); ATT&CK T1499.003; OWASP API API4:2023

### apigw-04: Route with no authorization reads the DynamoDB table

- **Resource:** `orders-api`
- **Tier and kind:** controlled, dangerous
- **What it is:** An orders API on a deployed stage of a regional API.
- **What is wrong:** GET /items has authorization_type NONE and calls DynamoDB Scan with an execution role, so anyone can read every item. CRITICAL is accepted because Vista may group this finding with apigw-05, which has the same root cause.
- **Expected rating:** category ACCESS_CONTROL, likelihood HIGH, impact MEDIUM, severity HIGH
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** OWASP API API2:2023
- **Note:** APIGateway.8 covers HTTP and WebSocket routes only. CRITICAL is accepted because Vista may group this with apigw-05, which has the same root cause.

### apigw-05: Routes with no authorization read, write, and delete DynamoDB items

- **Resource:** `loyalty-points-api`
- **Tier and kind:** controlled, dangerous
- **What it is:** A loyalty-points API.
- **What is wrong:** GET, PUT, and DELETE /items all have authorization_type NONE and call Scan, PutItem, and DeleteItem, so anyone can steal, tamper with, or destroy the data.
- **Expected rating:** category ACCESS_CONTROL, likelihood HIGH, impact HIGH, severity CRITICAL
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1485, T1565.001; OWASP API API2:2023, API5:2023

### apigw-06: Cognito-protected API with an anonymous MOCK health check

- **Resource:** `customer-api`
- **Tier and kind:** realistic, expected
- **What it is:** A customer API. GET and PUT /items use a Cognito user pool authorizer, with WAF, throttling, logging, and request validation. GET /health is anonymous but backed by a MOCK integration that touches no data.
- **What is wrong:** Nothing. Vista's guidance says an anonymous MOCK health check is not a finding on its own.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** none apply

### apigw-07: Partner API protected only by an API key

- **Resource:** `partner-api`
- **Tier and kind:** realistic, dangerous
- **What it is:** A partner API where GET and PUT /items have authorization_type NONE and api_key_required true.
- **What is wrong:** A usage plan throttles and caps the key, but an API key identifies a caller instead of authenticating one (OWASP API2:2023), and a leaked key can read and write the table. Obtaining a key is one precondition, so likelihood is MEDIUM. Vista's prompt treats API-key-only routes as HIGH likelihood, so this scenario directly tests that rule.
- **Expected rating:** category ACCESS_CONTROL, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1565.001; OWASP API API2:2023
- **Note:** CCSS treats obtaining the key as a precondition (MEDIUM likelihood). Vista's prompt treats API-key-only routes as HIGH likelihood, so this scenario directly tests that prompt rule.

### apigw-08: Unauthenticated admin API restricted to the office IP range

- **Resource:** `internal-admin-api`
- **Tier and kind:** realistic, ambiguous
- **What it is:** An internal admin API where GET and DELETE /items have no authorization, but the resource policy denies every source outside the office CIDR.
- **What is wrong:** Network location replaces identity, so anyone on the office network can delete data. The model should credit the allowlist and recommend real authorization instead of calling the API Internet-exposed.
- **Expected rating:** category ACCESS_CONTROL, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REVIEW (acceptable: REVIEW)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** ATT&CK T1485; OWASP API API2:2023, API5:2023
- **Context override:** The resource policy denies every source outside the office CIDR.

### apigw-09: HTTP API webhook route with no authorization that writes to SQS

- **Resource:** `webhooks`
- **Tier and kind:** realistic, ambiguous
- **What it is:** An HTTP API webhook route, POST /webhooks/payments, that is anonymous and sends the request body to an SQS queue.
- **What is wrong:** Payment providers usually sign webhooks and the signature is checked downstream, which the data cannot show. Anyone can inject messages but cannot read anything. A missing WAF must not be reported, because HTTP APIs cannot attach one.
- **Expected rating:** category ACCESS_CONTROL, likelihood HIGH, impact LOW, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM, HIGH
- **Expected action:** REVIEW (acceptable: REVIEW)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP APIGateway.8 (reference severity MEDIUM); ATT&CK T1565.001; OWASP API API2:2023

## RDS scenarios

### rds-01: Private instance with unencrypted storage

- **Resource:** `analytics-db`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private analytics database with publicly_accessible false and no security group rule.
- **What is wrong:** Storage is unencrypted. Reading it or its backups needs prior account access.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP RDS.3 (reference severity MEDIUM); ATT&CK T1578.001

### rds-02: Private instance that does not enforce TLS

- **Resource:** `billing-db`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private billing database.
- **What is wrong:** rds.force_ssl is 0, so clients can connect without encryption and credentials or data can be read in transit. Exploiting it needs a network position inside the VPC first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1040
- **Note:** No FSBP control covers rds.force_ssl.

### rds-03: Private instance with an associated role that writes to the exports bucket

- **Resource:** `events-db`
- **Tier and kind:** controlled, dangerous
- **What it is:** A private events database with an associated s3Export role limited to one exports bucket.
- **What is wrong:** Anyone who can run SQL can copy data out to S3. Vista sees only the role ARN and the feature, not the policy, so it may rate this lower.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** none apply

### rds-04: Public instance with port 5432 open to 0.0.0.0/0

- **Resource:** `crm-db`
- **Tier and kind:** controlled, dangerous
- **What it is:** A CRM database with publicly_accessible true.
- **What is wrong:** The security group allows port 5432 from anywhere, the subnet routes to an Internet gateway, and the network ACL allows it. Logging in still needs the Secrets Manager password or an IAM token.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact MEDIUM, severity HIGH
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP RDS.2, EC2.19 (reference severity CRITICAL); ATT&CK T1110

### rds-05: Unencrypted manual snapshot shared with all AWS accounts

- **Resource:** `staging-db-pre-migration`
- **Tier and kind:** controlled, dangerous
- **What it is:** A manual snapshot of a staging database whose source instance is private.
- **What is wrong:** The snapshot is unencrypted and shared_with contains all, so any AWS account can restore it and read all of its data. The finding is about the snapshot, not the instance.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood HIGH, impact HIGH, severity CRITICAL
- **Acceptable severities:** HIGH, CRITICAL
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP RDS.1, RDS.4 (reference severity CRITICAL); ATT&CK T1537

### rds-06: Hardened orders database reachable only through its proxy

- **Resource:** `orders-db`
- **Tier and kind:** realistic, expected
- **What it is:** A hardened orders database: private, customer-managed KMS key, TLS enforced, IAM and Secrets Manager authentication, backups, and log exports. Its only inbound rule is from the proxy's security group.
- **What is wrong:** Nothing. Deletion protection is off for easy teardown and is excluded as a baseline item. Problems with the proxy belong to rds-07, not this instance.
- **Expected rating:** no finding (NONE); no category, likelihood, or impact
- **Acceptable severities:** NONE, LOW
- **Expected action:** NO_ACTION (acceptable: NO_ACTION, REMEDIATE)
- **Frameworks:** none apply

### rds-07: RDS Proxy with debug logging left on and TLS optional

- **Resource:** `orders-db-proxy`
- **Tier and kind:** realistic, dangerous
- **What it is:** An RDS Proxy in front of the orders database.
- **What is wrong:** debug_logging is true, which writes SQL statements to CloudWatch Logs, and require_tls is false, which lets clients connect in plaintext. The proxy is VPC-only, so both need internal access first.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** ATT&CK T1040
- **Note:** No RDS Proxy control appears in the FSBP RDS control list.

### rds-08: Public database open to a single office IP

- **Resource:** `bi-reporting-db`
- **Tier and kind:** realistic, ambiguous
- **What it is:** A BI reporting database with publicly_accessible true and an Internet route.
- **What is wrong:** Port 5432 is allowed only from one /32. Vista's guidance says a narrow /32 is not automatically HIGH. The model should note it and suggest a private path, not treat the database as world-open.
- **Expected rating:** category PUBLIC_EXPOSURE, likelihood LOW, impact MEDIUM, severity LOW
- **Acceptable severities:** LOW, MEDIUM
- **Expected action:** REVIEW (acceptable: REVIEW)
- **Deferral:** accepted (PARTIAL or INSUFFICIENT confidence counts as an appropriate deferral)
- **Frameworks:** FSBP RDS.2 (reference severity CRITICAL); ATT&CK T1110
- **Context override:** Port 5432 is allowed from a single /32 only, so EC2.19 passes and the publicly accessible flag alone does not open the database to the Internet.

### rds-09: Legacy MySQL with several compounding configuration gaps

- **Resource:** `legacy-inventory-db`
- **Tier and kind:** realistic, dangerous
- **What it is:** A private legacy MySQL database.
- **What is wrong:** Port 3306 is open to all of 10.0.0.0/8, require_secure_transport is OFF, the master password is static with no master_user_secret, IAM authentication is off, backups are kept for 1 day, and no logs are exported. Each gap alone is LOW or MEDIUM; together they make credential theft in transit and unrecoverable loss plausible.
- **Expected rating:** category SECURITY_CONFIGURATION, likelihood MEDIUM, impact MEDIUM, severity MEDIUM
- **Acceptable severities:** MEDIUM, HIGH
- **Expected action:** REMEDIATE (acceptable: REMEDIATE)
- **Frameworks:** FSBP RDS.9, RDS.10, RDS.11 (reference severity MEDIUM); ATT&CK T1040
