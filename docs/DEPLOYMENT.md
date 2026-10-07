# Deployment / Operations Runbook — Request Portal for AWS Service Quotas (Quota Tool) v3.36

Reader-facing operational documentation for the CloudFormation stack. Used both by open-source consumers (customers deploying the tool in their own accounts) and by AppSec reviewers evaluating the deploy path.

**License**: Apache-2.0
**Version**: v3.36
**Deploy from**: `cloudformation/quota-tool-template.yaml` in this repository (self-contained; Lambda code embedded inline).

---

## 1. What This Deploys

A single-region CloudFormation stack that provisions:

- 1× CloudFront distribution (with default `*.cloudfront.net` cert or custom domain)
- 1× S3 bucket (ToolBucket, SSE-KMS, versioning enabled, OAC-only access)
- 1× S3 bucket (LogsBucket, SSE-S3, 90-day lifecycle, retained on stack delete)
- 1× API Gateway REST API (`AuthorizationType: AWS_IAM`, stage `prod`)
- 3× Lambda functions:
  - `QuotaFunction` — user-facing handler (POST /prod/quota)
  - `DeployerFunction` — custom resource that populates static site content
  - `CloudFrontWafLambda` — custom resource that creates the CLOUDFRONT-scope WAF in us-east-1
- 1× Cognito User Pool + Identity Pool + AuthRole
- 2× WAFv2 WebACLs (REGIONAL for API GW, CLOUDFRONT scope)
- 1× KMS CMK (rotation enabled)
- 5× CloudWatch alarms
- 1× SNS alarm topic
- 4× CloudWatch Log Groups (all KMS-encrypted, 30-day retention)

Total: 39 CloudFormation resources at default parameter values.

---

## 2. Parameters at Deploy Time

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `ToolBucketName` | String | (required) | Must be globally unique |
| `AlarmEmail` | String | (optional) | Subscribes to the SNS alarm topic |
| `GeoAllowList` | CommaDelimitedList | `US` | ISO-3166-1 alpha-2 codes for CloudFront geo-restriction |
| `EnableApiGwExecutionLogs` | String | `false` | Regional singleton — set `true` only if no other stack in the region owns `AWS::ApiGateway::Account` |
| `EnableAdvancedSecurity` | String | `true` | Flips UserPool tier to PLUS (charged per MAU) |
| `AdvancedSecurityMode` | String | `AUDIT` | Options: `OFF`, `AUDIT`, `ENFORCED` |
| `MfaConfiguration` | String | `ON` | Options: `OFF`, `OPTIONAL`, `ON`. `ON` requires v3.16+ MFA_SETUP handler (this template has it) |
| `UserPoolDeletionProtection` | String | `ACTIVE` | Options: `ACTIVE`, `INACTIVE`. `ACTIVE` blocks naive `delete-stack` |
| `EnableCloudFrontWaf` | String | `true` | Toggles CloudFront-scope WAF |
| `CustomDomainName` | String | (blank) | Custom domain via `Route53AliasRecord` |
| `ACMCertificateArn` | String | (blank) | Required if `CustomDomainName` set; must be in us-east-1 |

---

## 3. Deploy Steps

### 3.1 Prerequisites

- AWS credentials with permissions to create IAM roles, KMS keys, WAF, Cognito, and Lambda resources
- If setting `EnableCloudFrontWaf: true`: the deployer role also needs to create WAF in us-east-1
- If setting `CustomDomainName`: an ACM certificate provisioned in us-east-1

### 3.2 Deploy

```bash
aws cloudformation create-stack \
  --stack-name quota-tool \
  --template-body file://quota-tool-template.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameters \
      ParameterKey=ToolBucketName,ParameterValue=<unique-bucket-name> \
      ParameterKey=AlarmEmail,ParameterValue=<your-alarm-email> \
      ParameterKey=GeoAllowList,ParameterValue=US
```

Stack creation typically completes in ~8-12 minutes. The CloudFront WAF and distribution provisioning are the longest steps.

### 3.3 Post-Deploy: Create the First User

By default, the User Pool disallows self-registration (`AdminCreateUserConfig.AllowAdminCreateUserOnly: true`). Create a user via CLI:

```bash
aws cognito-idp admin-create-user \
    --user-pool-id <UserPoolId from stack outputs> \
    --username <username> \
    --temporary-password 'TempPass!ChangeOnFirstUse' \
    --message-action SUPPRESS
```

First sign-in will:
1. Force password change (`NEW_PASSWORD_REQUIRED` challenge)
2. If `MfaConfiguration: ON`, prompt for TOTP enrollment (`MFA_SETUP` challenge). QR code rendered inline via bundled `qrcode-generator@1.4.4`.
3. Land the user on the quota portal

### 3.4 Confirm Deployment

Fetch stack outputs and open the SiteURL:

```bash
aws cloudformation describe-stacks --stack-name quota-tool \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
```

Key outputs:
- `SiteURL` — the CloudFront distribution URL (or custom domain)
- `ApiEndpoint` — the API Gateway invoke URL
- `UserPoolId`, `UserPoolClientId`, `IdentityPoolId` — for admin operations
- `DistributionId` — for CloudFront cache invalidation
- `ProjectKeyArn` — the project KMS CMK

---

## 4. Rotate MFA / Reset Users

Reset user password:
```bash
aws cognito-idp admin-set-user-password \
    --user-pool-id <UserPoolId> --username <user> \
    --password '<new-temp-password>' --no-permanent
```

Force TOTP re-enrollment (removes existing enrolled devices):
```bash
aws cognito-idp admin-set-user-mfa-preference \
    --user-pool-id <UserPoolId> --username <user> \
    --software-token-mfa-settings Enabled=true,PreferredMfa=true
# Then the user must re-enroll on next sign-in via the MFA_SETUP flow
```

---

## 5. Invalidate CloudFront Cache

After updating `static-site/index.html` or `static-site/questions.json`:

```bash
aws cloudfront create-invalidation \
    --distribution-id <DistributionId> \
    --paths '/index.html' '/questions.json'
```

---

## 6. Teardown

The template is intentionally hard to delete accidentally. Full teardown requires:

### 6.1 Disable UserPool Deletion Protection

```bash
aws cognito-idp update-user-pool \
    --user-pool-id <UserPoolId> \
    --deletion-protection INACTIVE
```

(Requires `boto3>=1.27`. AWS CLI v1.x may not support `--deletion-protection` — use a boto3 script if the CLI rejects it.)

### 6.2 Empty Both Versioned Buckets

Both `ToolBucket` and `LogsBucket` are versioned. Delete versions AND delete markers:

```bash
for B in <ToolBucketName> <LogsBucketName>; do
  aws s3api list-object-versions --bucket "$B" \
    --query 'Versions[].{Key:Key,VersionId:VersionId}' --output json > /tmp/v.json
  [ "$(jq 'length // 0' /tmp/v.json)" -gt 0 ] && \
    aws s3api delete-objects --bucket "$B" --delete file:///tmp/v.json
  # Repeat for DeleteMarkers
done
```

### 6.3 Delete the Stack

```bash
aws cloudformation delete-stack --stack-name quota-tool
aws cloudformation wait stack-delete-complete --stack-name quota-tool
```

### 6.4 Handle Deployer-Created Delete Markers

The `DeployerFunction` custom resource writes new delete markers to `ToolBucket` during its Delete handler. If `delete-stack` fails with "bucket not empty", re-run step 6.2 for `ToolBucket` and re-issue `delete-stack`.

### 6.5 Clean Up Retained Resources

- `LogsBucket` has `DeletionPolicy: Retain` — empty and `aws s3 rb` manually
- Lambda log groups can outlive stack delete — sweep prefixes `/aws/lambda/<stack>-*`, `/aws/apigateway/<stack>-*`, `aws-waf-logs-<stack>-*`

### 6.6 CloudFront WAF (if EnableCloudFrontWaf was true)

Deletion can take 5-15 minutes; the `CloudFrontWafLambda` has a retry loop. If it times out:

```bash
aws wafv2 delete-web-acl --scope CLOUDFRONT --region us-east-1 \
    --name <stack>-cf-acl --id <WafId> \
    --lock-token "$(aws wafv2 get-web-acl --scope CLOUDFRONT --region us-east-1 \
                      --name <stack>-cf-acl --id <WafId> \
                      --query LockToken --output text)"
```

---

## 7. Update the Tool

To update from vN.M to vN.M+1:

```bash
aws cloudformation update-stack \
  --stack-name quota-tool \
  --template-body file://quota-tool-template-vN.M+1.yaml \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ToolBucketName,UsePreviousValue=true \
               ParameterKey=AlarmEmail,UsePreviousValue=true \
               ParameterKey=GeoAllowList,UsePreviousValue=true \
               # ... all other parameters use UsePreviousValue=true
```

For data-only releases (like v3.18-v3.36 questions.json updates), only the `DeployerFunction` custom resource re-runs — no infrastructure changes. Invalidate `/questions.json` and `/index.html` in CloudFront afterward.

---

## 8. Observability

**CloudWatch Alarms** (all → SNS topic):

| Alarm | Threshold | Action if triggered |
|---|---|---|
| API GW 4XX rate | > 10 in 5 min | Check WAF blocks; likely unauthorized requests |
| API GW 5XX rate | > 5 in 5 min | Check Lambda errors; possible dependency issue |
| Lambda Errors (any function) | > 3 in 5 min | Check Lambda logs |
| Lambda Throttles | > 0 in 5 min | Increase `ReservedConcurrentExecutions` if legitimate |
| WAF BlockedRequests | > 50 in 5 min | Check WAF logs; possible attack in progress |

**X-Ray tracing**: Active mode on API stage + all 3 Lambdas. Traces available in X-Ray console filtered by service name.

**CloudFront + S3 access logs**: separate `LogsBucket`, 90-day retention.

---

## 9. Common Operational Issues

The following are common operational behaviors to be aware of when running this stack:

1. **API GW resource policy takes ~5 min to propagate** after stack update.
2. **CloudFront WAF association delays deletion 5-15 min** — expected behavior.
3. **`EnableApiGwExecutionLogs` is a regional singleton** — only one stack per region can own the `AWS::ApiGateway::Account` resource.
4. **UserPool Advanced Security requires `PLUS` tier** — costs $0.05/MAU with no free tier.
5. **CloudFront default cert has TLSv1+ minimum**; set `CustomDomainName` + `ACMCertificateArn` for TLSv1.2_2021 enforcement.

---

## 10. Contact / Support

- **License questions**: see `LICENSE` (Apache-2.0) and `NOTICE`
- **Security issues**: `SECURITY.md` describes the coordinated disclosure process (email `security@amazon.com`)
- **Bug reports / feature requests**: GitHub Issues on the public repository (available after Type 2 launch completes)
