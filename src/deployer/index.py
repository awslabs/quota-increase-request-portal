# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json, boto3, gzip, base64, urllib.request

PHYS_ID = 'quota-tool-html-deployer'

def handler(event, context):
  try:
    bucket = event['ResourceProperties']['Bucket']
    s3 = boto3.client('s3')

    if event['RequestType'] == 'Delete':
      for key in ('index.html', 'questions.json'):
        try:
          s3.delete_object(Bucket=bucket, Key=key)
        except Exception as e:
          print(f'delete {key} failed (continuing): {e}')
      send(event, context, 'SUCCESS')
      return

    props = event['ResourceProperties']

    # Deploy index.html (gzip+base64, with %%API_URL%% + %%COGNITO_CONFIG%% substitution)
    html = gzip.decompress(base64.b64decode(props['HtmlGzB64'])).decode('utf-8')
    html = html.replace('%%API_URL%%', props['ApiUrl'])
    html = html.replace('%%COGNITO_CONFIG%%', props['CognitoConfig'])
    s3.put_object(
      Bucket=bucket, Key='index.html',
      Body=html.encode('utf-8'), ContentType='text/html',
      CacheControl='no-cache, no-store, must-revalidate')

    # Deploy questions.json (gzip+base64, stored raw - no substitution)
    qjson_b64 = props.get('QuestionsJsonGzB64')
    if qjson_b64:
      qjson = gzip.decompress(base64.b64decode(qjson_b64))
      s3.put_object(
        Bucket=bucket, Key='questions.json',
        Body=qjson, ContentType='application/json',
        CacheControl='no-cache, no-store, must-revalidate')

    send(event, context, 'SUCCESS')
  except Exception as e:
    print(e)
    send(event, context, 'FAILED', str(e))

def send(event, context, status, reason=''):
  body = json.dumps(dict(
    Status=status, Reason=reason or 'OK',
    PhysicalResourceId=PHYS_ID,
    StackId=event['StackId'], RequestId=event['RequestId'],
    LogicalResourceId=event['LogicalResourceId']
  )).encode()
  req = urllib.request.Request(event['ResponseURL'], data=body,
    headers={'content-type':''}, method='PUT')
  urllib.request.urlopen(req)  # nosec B310 - CFN response URL, not user-controlled
