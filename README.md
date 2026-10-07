# Request Portal for AWS Service Quotas

Self-contained CloudFormation template + browser frontend for submitting
AWS Service Quota increase requests. The full UI, backend, and supporting
assets are embedded in the template — no external artifacts required.

See [`CHANGELOG.md`](CHANGELOG.md) for the release history.

---

## What this tool does

Fully self-contained web tool for submitting AWS Service Quota increase requests. Users can:
- Browse all AWS services and their quotas
- Look up current quota values across multiple regions
- Submit a single consolidated support case for quota increases in multiple regions at once
- Get intelligent categoryCode resolution that matches the target service (not just the generic `service-limit-increase` fallback)

## Architecture

```
User → CloudFront (your distribution)
         │
         ├── GET /index.html ──► S3 bucket (quota-increase-tool-<account-id>) via OAC
         │
         └── POST /prod/quota ──► API Gateway (your stack) ──► Lambda (quota-tool-handler)
                                                                      │
                                                                      ├─► service-quotas API (list/get quotas, regions)
                                                                      ├─► ec2.DescribeRegions
                                                                      └─► support.CreateCase (one consolidated case)
```

A second Lambda (`quota-tool-deployer`) runs as a CloudFormation custom resource to deploy the gzip-base64 encoded `index.html` **and `questions.json`** (the 253KB service-to-question mapping used by the frontend's service autocomplete) to S3 at stack create/update time. Both assets are embedded in the template — nothing external required.

---

## Package layout

```
quota-tool-package/
├── README.md                               ← this file
├── cloudformation/
│   └── quota-tool-template.yaml           ← full CFN template — single source of truth
├── lambda-handler/
│   ├── quota-tool-handler.zip             ← exact running code (3205 bytes)
│   └── index.py                           ← unzipped source — main backend handler
├── lambda-deployer/
│   ├── quota-tool-deployer.zip            ← exact running code (737 bytes)
│   └── index.py                           ← unzipped source — custom-resource HTML deployer
├── lambda-cf-waf/                          ← docs for the inline custom-resource
│   ├── index.py                           ← creates / updates / deletes the CloudFront WAF (us-east-1)
│   └── README.md
└── static-site/
    ├── index.html                         ← frontend (vanilla JS, no framework)
    └── questions.json                     ← service-to-question mapping (~900 KB)
```

---

## Stack resources (39 at default settings)

Resources are grouped by what they do. Logical IDs match the CFN template; physical IDs are stack-generated.

**Static site (S3 + CloudFront):**
| Logical ID | Type |
|---|---|
| `ToolBucket` | `AWS::S3::Bucket` |
| `ToolBucketPolicy` | `AWS::S3::BucketPolicy` |
| `OriginAccessControl` | `AWS::CloudFront::OriginAccessControl` |
| `Distribution` | `AWS::CloudFront::Distribution` |
| `SecurityHeadersPolicy` | `AWS::CloudFront::ResponseHeadersPolicy` |

**API + Lambda backend:**
| Logical ID | Type |
|---|---|
| `QuotaApi` | `AWS::ApiGateway::RestApi` |
| `QuotaResource` | `AWS::ApiGateway::Resource` |
| `QuotaMethod` | `AWS::ApiGateway::Method` (POST) |
| `QuotaOptionsMethod` | `AWS::ApiGateway::Method` (OPTIONS) |
| `ApiDeployment` | `AWS::ApiGateway::Deployment` |
| `ApiStage` | `AWS::ApiGateway::Stage` |
| `LambdaApiPermission` | `AWS::Lambda::Permission` |
| `LambdaRole` | `AWS::IAM::Role` |
| `QuotaFunction` | `AWS::Lambda::Function` |
| `QuotaFunctionLogGroup` | `AWS::Logs::LogGroup` (30-day retention) |
| `DeployerRole` | `AWS::IAM::Role` |
| `DeployerFunction` | `AWS::Lambda::Function` |
| `DeployerFunctionLogGroup` | `AWS::Logs::LogGroup` (30-day retention) |
| `DeployHtml` | `Custom::DeployHtml` (deploys index.html + questions.json) |

**Cognito (auth):**
| Logical ID | Type |
|---|---|
| `UserPool` | `AWS::Cognito::UserPool` (Tier: PLUS when advanced security on, else ESSENTIALS) |
| `UserPoolClient` | `AWS::Cognito::UserPoolClient` |
| `IdentityPool` | `AWS::Cognito::IdentityPool` |
| `IdentityPoolRoleAttachment` | `AWS::Cognito::IdentityPoolRoleAttachment` |
| `AuthRole` | `AWS::IAM::Role` |

**WAFv2 (regional, attached to API stage):**
| Logical ID | Type |
|---|---|
| `QuotaApiWebACL` | `AWS::WAFv2::WebACL` |
| `QuotaApiWebACLAssociation` | `AWS::WAFv2::WebACLAssociation` |

**Observability (Tier 3):**
| Logical ID | Type |
|---|---|
| `AlarmTopic` | `AWS::SNS::Topic` |
| `AlarmEmailSubscription` | `AWS::SNS::Subscription` (only if `AlarmEmail` is set) |
| `Api4XXAlarm`, `Api5XXAlarm` | `AWS::CloudWatch::Alarm` |
| `HandlerErrorsAlarm`, `HandlerThrottlesAlarm` | `AWS::CloudWatch::Alarm` |
| `WafBlockedAlarm` | `AWS::CloudWatch::Alarm` |

**API Gateway execution logs (Tier 3, opt-in via `EnableApiGwExecutionLogs=true`):**
| Logical ID | Type |
|---|---|
| `ApiGwCloudWatchRole` | `AWS::IAM::Role` |
| `ApiGwAccount` | `AWS::ApiGateway::Account` (regional singleton — see Deploy notes) |

**CloudFront WAFv2 (Tier 3, default on, custom resource):**
| Logical ID | Type |
|---|---|
| `CloudFrontWafLambdaRole` | `AWS::IAM::Role` |
| `CloudFrontWafLambdaLogGroup` | `AWS::Logs::LogGroup` |
| `CloudFrontWafLambda` | `AWS::Lambda::Function` (creates the WebACL in `us-east-1`) |
| `CloudFrontWebACL` | `AWS::CloudFormation::CustomResource` (returns the WebACL ARN) |


## Stack outputs

| Key | Description |
|---|---|
| SiteURL | CloudFront URL (`https://<dist>.cloudfront.net`) — open this in a browser to use the tool |
| ApiEndpoint | API Gateway URL (`https://<api>.execute-api.<region>.amazonaws.com/prod/quota`) |
| BucketName | S3 bucket holding the static site (`quota-increase-tool-<account-id>` by default; override with `ToolBucketName`) |
| DistributionId | CloudFront distribution ID — needed for cache invalidations |
| UserPoolId / UserPoolClientId / IdentityPoolId / AuthRoleArn | Cognito identifiers — used for the `admin-create-user` command (see `CreateUserCmd` output) |
| CreateUserCmd | Pre-formatted `aws cognito-idp admin-create-user` command — substitute USERNAME and TEMP_PW and run to create a user |
| AlarmTopicArn | SNS topic for CloudWatch alarms — subscribe additional consumers here |
| CloudFrontWebACLArn | ARN of the CLOUDFRONT-scoped WAF WebACL (lives in us-east-1; only present when `EnableCloudFrontWaf=true`) |

---

## Lambda backend (`quota-tool-handler`)

**Runtime:** python3.12 | **Memory:** 256 MB | **Timeout:** 60s | **Code size:** 3205 bytes

Endpoints (POST body `action`):
- `list-regions` — returns all enabled regions via `ec2.DescribeRegions`
- `list-services` — paginates `service-quotas.ListServices` for a region
- `list-quotas` — merges `ListAWSDefaultServiceQuotas` + `ListServiceQuotas` for full catalog with applied values
- `lookup` — `GetServiceQuota` across multiple regions, falls back to default when no applied value
- `submit` (default) — builds one consolidated case body and calls `support.CreateCase` with intelligent `categoryCode` resolution

The `_resolve_category_code()` function is the key intelligence: it caches the categories inside the `service-limit-increase` Support service, then matches the frontend-supplied `itemCode` (exact) or fuzzy-matches service name/code against category names, with graceful fallback to `service-limit-increase`.

## Lambda custom resource (`quota-tool-deployer`)

**Runtime:** python3.12 | **Memory:** 128 MB | **Timeout:** 60s | **Code size:** 737 bytes

Called by CloudFormation at stack create/update/delete. On create/update: decodes the gzip+base64 encoded `index.html` embedded in the template (substituting `%%API_URL%%` with the live API Gateway URL) and the gzip+base64 encoded `questions.json`, and writes both to the `ToolBucket`. On delete: removes both objects. Both files are fully embedded in the template — redeployment to a fresh account requires no external assets.

## IAM permissions

**Lambda handler role (`quota-tool-lambda-role`):**
- Managed: `AWSLambdaBasicExecutionRole`
- Inline (`QuotaToolPermissions`): five read-only `servicequotas:` actions (`ListServices`, `ListServiceQuotas`, `ListAWSDefaultServiceQuotas`, `GetServiceQuota`, `GetAWSDefaultServiceQuota`), `support:CreateCase`, `support:DescribeCases`, `support:AddAttachmentsToSet`, `ec2:DescribeRegions`, `kms:Decrypt` (project CMK), `xray:PutTraceSegments`/`PutTelemetryRecords`

**Deployer role (`quota-tool-deployer-role`):**
- Managed: `AWSLambdaBasicExecutionRole`
- Inline (`S3Write`): `s3:PutObject`, `s3:DeleteObject` on `ToolBucket/*`

---

## How to re-deploy from this package

**Option 1 — Re-deploy the whole stack to a new account:**
```bash
aws cloudformation create-stack \
    --stack-name quota-tool \
    --template-body file://cloudformation/quota-tool-template.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --region us-east-1
```
The template is fully self-contained. Both Lambda functions are inlined as `ZipFile`, and the HTML **and `questions.json`** are embedded gzip+base64 inside the `DeployHtml` custom resource — the stack will deploy all static assets on its own, no S3 uploads or Option 2 step required.

**Option 2 — Just re-push the static site (if you want to update HTML without stack update):**

⚠️ `static-site/index.html` contains TWO placeholders that the deployer Lambda substitutes at stack-create time: `%%API_URL%%` (the API Gateway URL) and `%%COGNITO_CONFIG%%` (a JSON object with `region`/`userPoolId`/`clientId`/`identityPoolId`). The static file is not directly usable without both substitutions. **Use Option 1 (stack create/update) — Option 2 is impractical because the Cognito config JSON has to be constructed from four separate stack outputs and is regenerated on stack updates.**

```bash
# For the original account (no substitution needed):
BUCKET=$(aws cloudformation describe-stacks --stack-name quota-tool \
    --query 'Stacks[0].Outputs[?OutputKey==`BucketName`].OutputValue' --output text)
DIST_ID=$(aws cloudformation describe-stacks --stack-name quota-tool \
    --query 'Stacks[0].Outputs[?OutputKey==`DistributionId`].OutputValue' --output text)
aws s3 cp static-site/index.html "s3://$BUCKET/index.html" \
    --content-type text/html --cache-control "no-cache, no-store, must-revalidate"
aws s3 cp static-site/questions.json "s3://$BUCKET/questions.json" \
    --content-type application/json
aws cloudfront create-invalidation --distribution-id "$DIST_ID" --paths "/*"

# For a DIFFERENT account, substitute the API URL first:
```

**Option 3 — Update just the handler Lambda:**
```bash
# Edit lambda-handler/index.py, then:
cd lambda-handler && zip -r quota-tool-handler.zip index.py && \
aws lambda update-function-code --function-name quota-tool-handler \
    --zip-file fileb://quota-tool-handler.zip --region us-east-1
```
