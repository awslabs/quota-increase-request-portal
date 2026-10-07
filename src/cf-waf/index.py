# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3, json, time, urllib.request

waf = boto3.client('wafv2', region_name='us-east-1')

def _rules(name):
  return [
    {
      'Name': 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
      'Priority': 0,
      'OverrideAction': {'None': {}},
      'Statement': {'ManagedRuleGroupStatement': {
        'VendorName': 'AWS', 'Name': 'AWSManagedRulesKnownBadInputsRuleSet'}},
      'VisibilityConfig': {
        'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
        'MetricName': 'CF-KnownBadInputs'},
    },
    {
      'Name': 'AWS-AWSManagedRulesCommonRuleSet',
      'Priority': 1,
      'OverrideAction': {'None': {}},
      'Statement': {'ManagedRuleGroupStatement': {
        'VendorName': 'AWS', 'Name': 'AWSManagedRulesCommonRuleSet'}},
      'VisibilityConfig': {
        'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
        'MetricName': 'CF-CommonRuleSet'},
    },
    {
      'Name': 'RateLimitPerIP',
      'Priority': 2,
      'Action': {'Block': {}},
      'Statement': {'RateBasedStatement': {
        'Limit': 1000, 'AggregateKeyType': 'IP'}},
      'VisibilityConfig': {
        'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
        'MetricName': 'CF-RateLimit'},
    },
  ]

def _send(event, status, data=None, physical_id=None, reason=None):
  body = json.dumps({
    'Status': status,
    'Reason': reason or 'See CloudWatch logs',
    'PhysicalResourceId': physical_id or event.get('PhysicalResourceId') or 'cfwaf-init',
    'StackId': event['StackId'],
    'RequestId': event['RequestId'],
    'LogicalResourceId': event['LogicalResourceId'],
    'NoEcho': False,
    'Data': data or {},
  }).encode()
  req = urllib.request.Request(event['ResponseURL'], data=body, method='PUT',
                                headers={'Content-Type': '', 'Content-Length': str(len(body))})
  urllib.request.urlopen(req).read()  # nosec B310 - CFN response URL, not user-controlled

def handler(event, context):
  try:
    op = event['RequestType']
    name = event['ResourceProperties']['Name']
    if op == 'Create':
      r = waf.create_web_acl(
        Name=name, Scope='CLOUDFRONT',
        DefaultAction={'Allow': {}},
        VisibilityConfig={
          'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
          'MetricName': name.replace('-', '_')[:128],
        },
        Rules=_rules(name))
      arn = r['Summary']['ARN']
      pid = f"{name}|{r['Summary']['Id']}"
      _send(event, 'SUCCESS', {'WebACLArn': arn, 'WebACLId': r['Summary']['Id']},
            physical_id=pid)
    elif op == 'Update':
      # Find the existing WebACL by physical id (name|id)
      pid = event['PhysicalResourceId']
      if '|' in pid:
        _name, wid = pid.split('|', 1)
      else:
        _name, wid = name, pid
      cur = waf.get_web_acl(Name=_name, Scope='CLOUDFRONT', Id=wid)
      waf.update_web_acl(
        Name=_name, Scope='CLOUDFRONT', Id=wid,
        LockToken=cur['LockToken'],
        DefaultAction={'Allow': {}},
        VisibilityConfig={
          'SampledRequestsEnabled': True, 'CloudWatchMetricsEnabled': True,
          'MetricName': _name.replace('-', '_')[:128],
        },
        Rules=_rules(_name))
      arn = cur['WebACL']['ARN']
      _send(event, 'SUCCESS', {'WebACLArn': arn, 'WebACLId': wid}, physical_id=pid)
    elif op == 'Delete':
      pid = event['PhysicalResourceId']
      if pid and pid != 'cfwaf-init' and '|' in pid:
        _name, wid = pid.split('|', 1)
        for _ in range(20):  # CloudFront takes a while to release the association
          try:
            cur = waf.get_web_acl(Name=_name, Scope='CLOUDFRONT', Id=wid)
            waf.delete_web_acl(Name=_name, Scope='CLOUDFRONT', Id=wid,
                                LockToken=cur['LockToken'])
            break
          except waf.exceptions.WAFAssociatedItemException:
            time.sleep(15)
          except waf.exceptions.WAFNonexistentItemException:
            break
      _send(event, 'SUCCESS', physical_id=pid)
    else:
      _send(event, 'FAILED', reason=f'Unknown RequestType: {op}')
  except Exception as e:
    _send(event, 'FAILED', reason=f'{type(e).__name__}: {e}')
