# Architecture

The Request Portal for AWS Service Quotas is a self-contained, single-region
AWS CloudFormation stack. It gives authenticated users a web UI to submit AWS
service-quota increase requests without granting them AWS Management Console
access — the stack exposes exactly one narrow API operation.

## Component overview

```
[ Browser ] --HTTPS--> [ CloudFront ] --OAC--> [ S3 (static site) ]
      |
      +----HTTPS----> [ API Gateway (AWS_IAM auth) ] --invoke--> [ Lambda handler ]
                                                                        |
                                                                        +-- service-quotas  (read/list)
                                                                        +-- ec2:DescribeRegions
                                                                        +-- support:CreateCase / AddAttachmentsToSet
```

- **CloudFront + S3** — serves the single-page static UI (`index.html`,
  `questions.json`). S3 is reachable only through the distribution via Origin
  Access Control; the bucket policy grants `s3:GetObject` to the distribution
  only.
- **Amazon Cognito** — a User Pool (admin-created users, no self-signup, TOTP
  MFA) authenticates users. The UI exchanges User Pool tokens for short-lived
  AWS credentials through a Cognito Identity Pool.
- **API Gateway** — one `POST /prod/quota` endpoint with
  `AuthorizationType: AWS_IAM`. Every call is SigV4-signed with the federated
  credentials; unsigned requests are rejected before reaching Lambda. A
  resource policy restricts callers to the deploying account.
- **Lambda (handler)** — validates input, looks up quotas, and creates the
  support case. Two additional Lambdas are CloudFormation custom resources
  (one deploys the static content to S3, one creates the CloudFront-scope WAF
  in `us-east-1`).
- **WAFv2** — two Web ACLs (CloudFront scope in `us-east-1`, and REGIONAL for
  the API stage): managed KnownBadInputs + CommonRuleSet + a rate-limit rule,
  plus a geo-restriction allow-list (US by default, configurable).
- **KMS** — a customer-managed key encrypts the tool bucket, Lambda
  environment variables, and all CloudWatch log groups.

## Request flow

1. User signs in against the Cognito User Pool (password + TOTP MFA).
2. The UI exchanges the User Pool ID token via the Identity Pool for
   short-lived credentials scoped to a single IAM role (`AuthRole`).
3. `AuthRole` may only `execute-api:Invoke` this stack's
   `POST /prod/quota` — nothing else.
4. The browser SigV4-signs the request; API Gateway enforces IAM auth and the
   same-account resource policy.
5. The Lambda handler validates every field against a whitelist, then calls
   `service-quotas` (read), `ec2:DescribeRegions`, and `support:CreateCase`.

## Trust boundaries

| Boundary | Control |
|---|---|
| Internet → CloudFront | TLS (TLSv1.2_2021 with a custom domain + ACM cert; otherwise the AWS-managed default cert) |
| CloudFront → S3 | Origin Access Control; bucket policy scoped to the distribution |
| Browser → API Gateway | SigV4 + `AuthorizationType: AWS_IAM`; resource policy requires the caller principal be in the deploying account; `OPTIONS` exempted for CORS preflight |
| User Pool → Identity Pool → AuthRole | Trust policy requires this Identity Pool's `aud` and `amr == authenticated` |
| AuthRole → API Gateway | Policy scoped to the single `POST /prod/quota` ARN |
| Lambda → AWS APIs | Least-privilege inline policy: five read-only `servicequotas:` actions (`ListServices`/`ListServiceQuotas`/`ListAWSDefaultServiceQuotas`/`GetServiceQuota`/`GetAWSDefaultServiceQuota`), `support:CreateCase`/`DescribeCases`/`AddAttachmentsToSet`, `ec2:DescribeRegions`, `kms:Decrypt`, X-Ray put-only |

## Data handling

The tool processes only the deploying account's own data:

- **Sign-in tokens / TOTP secrets** live in Cognito and browser memory; never
  written to S3.
- **Justification text and attachments** flow browser → API Gateway → Lambda →
  AWS Support. Request bodies are not logged (`DataTraceEnabled: false`).
- **Static assets** are readable only by authenticated users; encrypted at
  rest with the project KMS key.

There is no PII beyond what a user types into a case justification, no payment
data, and no third-party (cross-account) customer data.

## Content-Security-Policy

The UI ships a strict CSP: `default-src 'self'`, `script-src 'self'` +
per-build SHA-256 hashes, `style-src 'self'` + per-build SHA-256 hashes — no
`'unsafe-inline'` on scripts and no remote origins. The one bundled
third-party library (`qrcode-generator`, for MFA QR rendering) is embedded
inline and covered by the script hash, so any modification breaks the deployed
page. See `THIRD-PARTY-LICENSES`.
