# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - TBD

Initial public release.

### Features

- Self-contained CloudFormation stack deploys a customer-facing web application for submitting AWS Service Quota increase requests.
- Interactive UI for browsing quotas across regions, entering requested values, and submitting a single consolidated support case that can cover multiple regions.
- Pre-configured quota entries with quota-specific justification questions covering the top AWS services.
- Case routing: opens support cases with the correct service-team category rather than the generic `service-limit-increase` fallback.
- Optional file attachments.

### Security

- CloudFront + Amazon Cognito authentication with configurable MFA (optional or required).
- SigV4 signature enforcement on every backend call (API Gateway `AWS_IAM` authorization).
- Strict Content Security Policy — no `unsafe-inline` or `unsafe-eval`; all inline scripts and styles are SHA-256 hash-pinned.
- Dual AWS WAFv2 Web ACLs (regional + CloudFront).
- KMS-encrypted state (S3 bucket, CloudWatch log groups, Lambda environment variables).
- Cognito user pool deletion protection enabled by default.
- Cognito advanced security in AUDIT mode by default (upgradable to ENFORCED at deploy time).
- CloudWatch alarms monitoring Lambda errors/throttles and WAF blocked requests, delivering to an SNS topic.
- Configurable geographic access restrictions on both API Gateway and CloudFront.

### Documentation

- `README.md` — quick start, architecture overview, feature list.
- `docs/DEPLOYMENT.md` — step-by-step deployment guide with prerequisites.
- `docs/ARCHITECTURE.md` — component diagram, request flow, security architecture.
- `docs/OPERATIONS.md` — user management, MFA rotation, CloudFront cache invalidation, teardown.
- `docs/THREAT_MODEL.md` — trust boundaries, abuse cases, accepted residual risks.
- `SECURITY.md` — vulnerability reporting process.
- `THIRD-PARTY-LICENSES` — attribution for the single bundled dependency (`qrcode-generator@1.4.4`, MIT).

### Third-Party Dependencies

- `qrcode-generator@1.4.4` (MIT, Kazuhiko Arase) — embedded inline in the authentication bundle for QR code rendering during MFA enrollment. Pure browser, no network calls.

[Unreleased]: https://github.com/awslabs/quota-increase-request-portal/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/awslabs/quota-increase-request-portal/releases/tag/v1.0.0
