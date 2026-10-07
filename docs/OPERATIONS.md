# Operations

Operational guidance for running the Request Portal for AWS Service Quotas
stack. Deployment and teardown steps are in [DEPLOYMENT.md](DEPLOYMENT.md);
this document covers day-2 operations, observability, and known operational
behaviors.

Throughout, `<stack>` is your CloudFormation stack name and `<region>` the
deploy region.

## Observability

**CloudWatch alarms** (all publish to the stack's SNS topic; subscribe an
email at deploy time via the `AlarmEmail` parameter):

| Alarm | Trigger | First thing to check |
|---|---|---|
| API GW 4XX | > 10 in 5 min | WAF blocks / unauthorized (unsigned) requests |
| API GW 5XX | > 5 in 5 min | Lambda handler errors / dependency issues |
| Lambda Errors | > 3 in 5 min | Handler CloudWatch logs |
| Lambda Throttles | > 0 in 5 min | Raise `ReservedConcurrentExecutions` if load is legitimate |
| WAF BlockedRequests | > 50 in 5 min | WAF logs — possible attack or misconfigured client |

**Logs** (all KMS-encrypted; 30-day retention unless noted):

| Source | Log group / location |
|---|---|
| Lambda functions | `/aws/lambda/<stack>-handler`, `-deployer`, `-cf-waf` |
| API Gateway access | `/aws/apigateway/<stack>-access` (JSON; request metadata only, no bodies) |
| API Gateway execution (errors) | `/aws/apigateway/<api-id>/prod` (only when `EnableApiGwExecutionLogs=true`) |
| WAFv2 regional (BLOCK) | `aws-waf-logs-<stack>-regional` |
| CloudFront + S3 access logs | separate logs bucket, 90-day lifecycle, SSE-S3 |

**X-Ray**: Active tracing on the API stage and all three Lambdas.

## User management

Users are admin-created (no self-signup). Use the `CreateUserCmd` stack output
for the exact command, or:

```bash
aws cognito-idp admin-create-user \
  --user-pool-id <UserPoolId> --username <username> \
  --temporary-password '<temp-pw>' --message-action SUPPRESS \
  --region <region>
```

First sign-in forces a password change, and — when `MfaConfiguration: ON` —
TOTP enrollment (QR rendered inline). Reset a password with
`admin-set-user-password`; force TOTP re-enrollment with
`admin-set-user-mfa-preference`. Disable a compromised user immediately with
`admin-disable-user`.

## Updating the tool

Data-only updates (new `questions.json`) re-run only the deployer custom
resource — no infrastructure change. After any update, invalidate the CDN:

```bash
aws cloudfront create-invalidation \
  --distribution-id <DistributionId> --paths '/index.html' '/questions.json'
```

Then confirm the served content matches your build (`sha256sum`), and that the
`Content-Security-Policy` response header hashes match the served `<script>`
and `<style>` blocks byte-for-byte if `index.html` changed.

## Known operational behaviors

These are expected, not bugs:

1. **API Gateway resource-policy changes take ~5 minutes to propagate** after
   the stack reports `UPDATE_COMPLETE`. Policy changes also require a
   stage-targeted redeployment — include `--stage-name prod`.
2. **`AWS::ApiGateway::Account` is a per-region singleton.** Only one stack per
   region can own it; set `EnableApiGwExecutionLogs=false` if another stack in
   the region already does.
3. **Cognito Advanced Security requires the `PLUS` user-pool tier**, billed per
   monthly active user (no free tier). Set `EnableAdvancedSecurity=false` to
   stay on `ESSENTIALS`.
4. **`MfaConfiguration: ON` is the default** and requires the current template
   (it handles the `MFA_SETUP` enrollment challenge). Existing users must
   enroll TOTP on next sign-in.
5. **CloudFront WAFv2 lives in `us-east-1`** regardless of stack region, and its
   deletion can take 5–15 minutes to release the association.
6. **The default `*.cloudfront.net` certificate enforces a TLSv1 minimum** (set
   by AWS). Set `CustomDomainName` + `ACMCertificateArn` (cert in `us-east-1`)
   to enforce TLSv1.2_2021.

## Teardown notes

The stack is intentionally hard to delete accidentally. Full teardown requires,
in order: (1) disable Cognito User Pool deletion protection; (2) empty **both**
versioned S3 buckets including delete markers; (3) `delete-stack`. Additional
cleanup: the deployer custom resource may write fresh delete markers to the
tool bucket during its Delete handler (re-empty and retry); the logs bucket has
`DeletionPolicy: Retain` (empty + `s3 rb` manually); and Lambda/API-GW/WAF log
groups can outlive the stack (sweep `/aws/lambda/<stack>-*`,
`/aws/apigateway/<stack>-*`, `aws-waf-logs-<stack>-*` before redeploying the
same name). See [DEPLOYMENT.md](DEPLOYMENT.md) for the exact commands.

## Cost

Idle cost is dominated by the Cognito `PLUS` tier (per-MAU) and WAFv2 (per Web
ACL + per-request inspection). Disabling advanced security and/or the
CloudFront WAF lowers idle cost; both are deploy-time parameters.
