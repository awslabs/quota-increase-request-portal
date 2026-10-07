# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you
notify AWS/Amazon Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or directly via email to aws-security@amazon.com.

**Please do _not_ create a public GitHub issue** for security-sensitive
reports, and please do not include sensitive details in issues or pull
requests.

We will acknowledge your report, investigate, and keep you informed of
remediation progress.

## Scope

This project deploys entirely within the operator's own AWS account and uses
only public AWS APIs — five read-only `servicequotas:` actions (`ListServices`,
`ListServiceQuotas`, `ListAWSDefaultServiceQuotas`, `GetServiceQuota`,
`GetAWSDefaultServiceQuota`), plus `support:CreateCase`/`DescribeCases`/
`AddAttachmentsToSet` and `ec2:DescribeRegions`. It does not transmit data outside the deploying
account. When reporting, please describe the deployed configuration
(template version, parameter values) so we can reproduce.

## Supported Versions

Security fixes are applied to the latest released version. Please upgrade to
the current release before reporting, where practical.
