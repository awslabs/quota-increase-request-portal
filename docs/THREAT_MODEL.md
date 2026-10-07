# Request Portal for AWS Service Quotas — Threat Model & Security Posture

This document describes the trust boundaries, abuse cases, controls, and accepted residual risks for the portal deployed by `cloudformation/quota-tool-template.yaml`.

It is intended for security teams and operators evaluating whether to deploy this template into their account.

---

## 1. System overview

The tool is a self-contained, single-region CloudFormation stack that gives authenticated users a web UI to submit AWS service-quota increase requests. The same UI normally requires console access; this stack grants narrow API access (one POST endpoint) without giving users console access.

```
[ Browser ] --HTTPS--> [ CloudFront ] --OAC-->            [ S3 (static site) ]
                  |
                  +--HTTPS-->  [ API Gateway (AWS_IAM auth) ] --invoke--> [ Lambda ]
                                                                                   |
                                                                                   +-- service-quotas (read)
                                                                                   +-- ec2:DescribeRegions
                                                                                   +-- support:CreateCase, AddAttachmentsToSet
```

Sign-in is performed against a Cognito User Pool. The UI then exchanges the User Pool tokens for short-lived AWS credentials via the Cognito Identity Pool, and signs every API call with SigV4. API Gateway enforces `AuthorizationType: AWS_IAM`, so unsigned requests are rejected before reaching the Lambda.

---

## 2. Trust boundaries

| Boundary | What crosses | Control |
|---|---|---|
| Internet → CloudFront | TLS termination | TLSv1.2_2021 minimum if `CustomDomainName` is set; otherwise the AWS-managed `*.cloudfront.net` cert (current AWS minimum is TLSv1) |
| CloudFront → S3 (static assets) | Origin Access Control (signed) | OAC; bucket policy grants `s3:GetObject` only to this distribution |
| Browser → API Gateway | SigV4-signed HTTPS request | API Gateway `AuthorizationType: AWS_IAM`; resource policy requires `aws:PrincipalAccount = <stack account>`; unauthenticated `OPTIONS` exempted explicitly for CORS preflight |
| Cognito User Pool → Identity Pool → AuthRole | Federated `AssumeRoleWithWebIdentity` | Trust policy requires `cognito-identity.amazonaws.com:aud == <this Identity Pool>` and `amr == authenticated` |
| AuthRole → API Gateway | SigV4-signed `execute-api:Invoke` | AuthRole policy is scoped to the single ARN: `arn:aws:execute-api:<region>:<acct>:<api>/prod/POST/quota` |
| Lambda → AWS APIs | IAM principal: `LambdaRole` | Inline policy is least-privilege: `servicequotas:*`, `support:CreateCase`, `support:AddAttachmentsToSet`, `support:DescribeServices`, `support:DescribeSeverityLevels`, `ec2:DescribeRegions`, `kms:Decrypt` (env var), `xray:PutTraceSegments`/`PutTelemetryRecords` |
| Edge → CloudFront | WAFv2 (CLOUDFRONT scope, us-east-1) | KnownBadInputs + CommonRuleSet + RateLimit; geo-restriction (US whitelist by default) |
| API Gateway → API stage | WAFv2 (REGIONAL) | Same rule set; logs on BLOCK to CloudWatch Logs |

---

## 3. Identity & access controls

| Control | Setting |
|---|---|
| Self-registration | **Disabled** (`AdminCreateUserConfig.AllowAdminCreateUserOnly: true`) |
| Account recovery | `admin_only` — no email/SMS reset paths |
| Password policy | 12 chars min, mixed case + numbers (symbols not required) |
| MFA | **Required by default** (`MfaConfiguration: ON`, TOTP only) |
| Existence enumeration | `PreventUserExistenceErrors: ENABLED` |
| Token validity | Access/ID 1 h, Refresh 8 h |
| Advanced Security | Cognito `PLUS` tier with `AdvancedSecurityMode: AUDIT` (compromised credentials, adaptive auth) |
| User Pool tier | `PLUS` (when advanced security is on) |

---

## 4. Abuse cases & mitigations

### 4.1 Unauthenticated case submission
- **Threat**: someone discovers the API endpoint and submits noise / abuse cases.
- **Mitigation**: API Gateway `AWS_IAM` + resource policy `aws:PrincipalAccount = <acct>` rejects all unsigned and cross-account requests. Even with the public CloudFront distribution, the API path requires SigV4 from a principal in the deploying account.
- **Residual**: An authenticated user (anyone in the User Pool the admin created) could submit requests. Supreme bound is the Lambda's IAM (only `support:CreateCase` and read-only quota lookups; no DescribeCases write, no ResolveCase).

### 4.2 Compromised User Pool user
- **Threat**: stolen TOTP seed or password.
- **Mitigation**: short token TTLs (1h), MFA required, `AUDIT` advanced security logs risk events for review, admin can disable user via `cognito-idp admin-disable-user`. Operators may graduate `AUDIT` → `ENFORCED` after a tuning period.
- **Residual**: AUDIT does not block sign-ins; only logs them. Customers needing automatic blocking should set `AdvancedSecurityMode: ENFORCED` at deploy time.

### 4.3 XSS via the portal's own UI
- **Threat**: an attacker injects script that runs in another authenticated user's session.
- **Mitigation (defense in depth)**:
  - `Content-Security-Policy: default-src 'self'`; `script-src 'self' <2 SHA-256 hashes>`; `style-src 'self' <3 SHA-256 hashes>` — no `'unsafe-inline'`, no remote origins.
  - All inline event handlers (`onclick=`, `onchange=`) replaced with `data-click`/`data-change` + a delegated listener.
  - All `style="…"` attributes refactored into named classes; CSP rejects anything else.
  - X-Content-Type-Options, X-Frame-Options DENY, Referrer-Policy: strict-origin-when-cross-origin, HSTS preload.
- **Residual**: a successful XSS would have to defeat CSP hash binding (requires byte-exact known scripts; any modification breaks the hash). Remote injection is impossible without compromising the build pipeline.
  - A third-party library (`qrcode-generator@1.4.4`) is embedded inline in the auth-bundle `<script>` block. The library bytes are included in the CSP-bound script hash, so any modification (intentional or supply-chain) breaks the deployed page. Library audited for active-path network calls (0 `fetch(`, `XMLHttpRequest`, `new Image`, `new WebSocket`, `navigator.send*`, `importScripts`) and `eval`/`new Function` (0 occurrences). See `THIRD-PARTY-LICENSES` for the dependency's attribution; its bytes are included in the CSP-bound script hash.

### 4.4 SSRF / abuse of the case-creation backend
- **Threat**: malformed payload triggers unintended AWS API calls or attaches arbitrary content to support cases.
- **Mitigation**:
  - Body size capped at 256 KB; per-field length limits (`justification` 8 KB, `quotaName` 256 chars).
  - Whitelist regexes on every identifier: `service` `^[a-z0-9-]{1,64}$`, `quotaCode` `^L-[A-Za-z0-9]{8}$`, `region` `^[a-z]{2}-[a-z]+-\d{1,2}$`, `fileName` `^[A-Za-z0-9_.\- ]{1,200}$` (no path separators).
  - Attachment count ≤ 3, total decoded size ≤ 5 MB (Support API limit).
  - Action allow-list: only `submit | lookup | list-quotas | list-services | list-regions`. Default action is `submit`.
- **Residual**: `_resolve_category_code` does fuzzy string matching; misclassification would route a case to the wrong service team but would not exfiltrate data or escalate privilege.

### 4.5 Resource exhaustion
- **Threat**: someone tries to drive up cost or deny service via volume.
- **Mitigation**:
  - WAFv2 RateLimit rule (CLOUDFRONT + REGIONAL).
  - API Gateway throttling at stage: 20 req/s steady, 50 burst.
  - Lambda `ReservedConcurrentExecutions`: handler 20, deployer 2, cf-waf 2 — caps blast radius.
  - CloudWatch alarms: API GW 4XX, 5XX, Lambda errors, Lambda throttles, WAF blocked, all → SNS topic.
- **Residual**: a determined attacker still pays for AWS WAF inspections + CloudFront edge requests up to the rate limit. CloudFront geo-restriction (US-only by default) further bounds this.

### 4.6 CloudFormation deploy abuse
- **Threat**: malicious template parameter tricks the stack into creating something unexpected.
- **Mitigation**:
  - All parameters have `AllowedValues` (booleans) or are typed (`String`/`CommaDelimitedList`).
  - `ToolBucketName`, `CustomDomainName`, `ACMCertificateArn` are echoed only into resource names / ARNs the stack already controls.
  - Custom resources (DeployHtml, CloudFrontWafLambda) accept properties only from the template, not from outside.
- **Residual**: someone with `CreateStack` permission already has account-wide power; this isn't a defended boundary.

### 4.7 Supply chain — embedded 3rd-party JavaScript
- **Threat**: a malicious version of an embedded 3rd-party library reaches a deployed stack and runs in users' browsers (compromised authenticators, exfiltration of TOTP codes).
- **Surface**: the only non-AWS dependency in the deployed package is `qrcode-generator@1.4.4` (MIT, ~57 KB) embedded inline in the auth-bundle `<script>` block. The 3 Lambdas use only Python stdlib + boto3 (runtime-provided by AWS); no requirements.txt / package.json / pinned vendored libs.
- **Mitigations**:
  - CSP `script-src 'self' <2 sha256 hashes>` — browser refuses to execute any script body other than the exact bytes hashed at build time. Any modification (legitimate or malicious) breaks the deployed page.
  - Library is included inline as source (not loaded from CDN, not imported from a registry at runtime).
  - Library audited for active-path network calls: 0 across `fetch`, `XHR`, `Image`, `WebSocket`, `navigator.send*`, `importScripts`.
  - The single third-party dependency is listed in `THIRD-PARTY-LICENSES` (name, version, license, upstream URL); its inline bytes are covered by the CSP-bound script hash.
- **Residual**: a build-pipeline compromise that swapped the library AND regenerated the CSP hashes would not be caught by the browser. **Defense**: the shipped `cloudformation/quota-tool-template.yaml` is self-contained and authoritative (Lambda inlined, static assets embedded as gzip+base64); release artifacts go through verification (cfn-lint + checkov + bandit + a hash diff of the served HTML vs the embedded `HtmlGzB64`). This is the same residual that applies to any inline-script CSP scheme.

---

## 5. Data flow & sensitivity

| Data | Where it lives | Sensitivity | Encryption |
|---|---|---|---|
| User name / TOTP secret | Cognito User Pool | High | Cognito-managed |
| Sign-in tokens (JWT) | Browser sessionStorage (session-scoped, cleared on tab close) + AWS STS | High, short-lived (1h); refresh token not persisted client-side | TLS in transit; tokens never written to S3 or server-side storage |
| Justification text + attachments | API Gateway → Lambda → AWS Support backend | Customer-controlled, may include account internals | TLS; logs disabled for request body (`DataTraceEnabled: false`) |
| Static site (`index.html`, `questions.json`) | S3 `ToolBucket` | Public-readable to authenticated users | SSE-KMS (CMK) at rest, TLS in transit |
| Lambda env vars (`ALLOWED_ORIGIN`) | Lambda config | Low (no secret) | KMS-encrypted (CMK) at rest |
| CloudWatch Logs (Lambda + access + WAF) | CWL log groups | Medium — request metadata only, no bodies | KMS-encrypted (CMK) |
| CloudFront / S3 access logs | `LogsBucket` (separate S3 bucket, retention 90d, versioning on) | Low (request metadata) | SSE-S3 |

No customer credentials, no payment data, no PII other than what users themselves put in the `justification` field of a case.

---

## 6. Logging & detection

| Source | Destination | Retention |
|---|---|---|
| Lambda function logs | `/aws/lambda/<stack>-handler`, `<stack>-deployer`, `<stack>-cf-waf` | 30 days, KMS-encrypted |
| API Gateway access logs (per request) | `/aws/apigateway/<stack>-access` | 30 days, KMS-encrypted |
| API Gateway execution logs (errors) | `/aws/apigateway/<api>/prod` | 30 days |
| WAFv2 regional (BLOCK only) | `aws-waf-logs-<stack>-regional` | 30 days, KMS-encrypted |
| CloudFront standard logs | `LogsBucket/cloudfront/` | 90 days, SSE-S3 |
| S3 server access logs (`ToolBucket`) | `LogsBucket/s3-access/` | 90 days, SSE-S3 |
| X-Ray traces | API Gateway + 3 Lambdas | 30 days (X-Ray default) |
| CloudWatch alarms → SNS | `<stack>-alarms` topic, KMS-encrypted | n/a |

---

## 7. Accepted residual risks

| Risk | Why accepted |
|---|---|
| **`Lambda` not in VPC** (CKV_AWS_117 ×3) | All three Lambdas only call public AWS APIs (servicequotas, support, ec2, kms). Putting them in a VPC adds NAT gateway cost (~$32/mo) for zero security gain on this threat model. |
| **No DLQ on Lambdas** (CKV_AWS_116 ×3) | All three Lambdas are sync-invoked (API Gateway, CloudFormation custom resource). DLQ is only meaningful for async invokers. |
| **API Gateway no caching** (CKV_AWS_120) | The single endpoint is POST and not idempotent (creates support cases). Caching would be wrong. |
| **CloudFront default cert is TLSv1+** (CKV_AWS_174) | Mitigated by setting `CustomDomainName` + `ACMCertificateArn` at deploy time, which forces TLSv1.2_2021. The `*.cloudfront.net` default cert TLS minimum is set by AWS, not the stack. |
| **Cognito `AdvancedSecurityMode: AUDIT`** | Default. Customers may set `ENFORCED` at deploy time; AUDIT is kept until risk-event metrics are observed in operation, then graduated. |
| **Logs bucket self-logging** | The `LogsBucket` does not log access to itself (would recurse). It is a pure write target with `BlockPublicAcls`/`BlockPublicPolicy`/`IgnorePublicAcls`/`RestrictPublicBuckets` all `true`. |

---

## 8. Out of scope

- AWS Support ticket lifecycle after creation (handled by AWS).
- Customer's own account-level controls (CloudTrail, SCP, GuardDuty) — assumed in place.
- DDoS at the AWS provider level (Shield Standard is automatic; Shield Advanced not enabled by this stack).

---

## 9. Verification & evidence

Static analysis is run against each release. On the current release:

- **`cfn-lint`**: clean — one informational `W1030` parameter-pattern warning on the optional `ACMCertificateArn` (only validated when `CustomDomainName` is also set). No error-level findings.

- **`checkov`** (CloudFormation framework): all failures are the documented residuals in §7 above:
  - `CKV_AWS_117` × 3 (Lambda not in VPC)
  - `CKV_AWS_116` × 3 (Lambda no DLQ)
  - `CKV_AWS_120` × 1 (API GW no caching)
  - `CKV_AWS_174` × 1 (CloudFront default cert TLS — mitigated at deploy time by setting `CustomDomainName` + `ACMCertificateArn`)
  - `CKV_AWS_18` on LogsBucket (self-logging recursion) is explicitly skipped via `Metadata.checkov.skip`.

- **`bandit`** on the 3 Lambda Python sources — **0 findings**. Manual review covers input validation regexes, body-size cap, attachment cap, ReDoS-safety of every regex (no nested quantifiers), and absence of `eval`/`exec`/`pickle`/`subprocess`. The two custom-resource Lambdas each carry one `# nosec B310` annotation on the CloudFormation-supplied pre-signed callback URL (false positive — URL is supplied by AWS at runtime).

- **Dependencies**: the 3 Lambdas use only the Python standard library + the AWS-provided boto3 runtime (no vendored packages). The single bundled browser library (`qrcode-generator@1.4.4`, MIT) is attributed in `THIRD-PARTY-LICENSES`.

- **CSP hash verification**: the `Content-Security-Policy` response header pins 2 `script-src` and 3 `style-src` SHA-256 hashes. Each hash is computed over the exact bytes of the corresponding inline `<script>`/`<style>` block. A deployer can verify integrity by recomputing the SHA-256 of each served block and comparing against the header — any drift between the served HTML and the pinned hashes indicates tampering.

- **Embedding integrity**: the template embeds `index.html` and `questions.json` as gzip+base64 blobs (`HtmlGzB64`, `QuestionsJsonGzB64`). Both decode byte-identically to the files under `static-site/`, and the inline Lambda `ZipFile` blocks are byte-identical to the sources under `src/`. These invariants are checked at release time.
