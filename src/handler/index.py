# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json, os, re, boto3

ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '*')
HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Amz-Date, X-Amz-Security-Token, X-Amz-Content-Sha256',
  'Vary': 'Origin',
}

# ========== Input validation ==========
MAX_BODY_BYTES   = 256 * 1024   # 256 KB request body cap (covers attachments + JSON overhead)
MAX_TEXT_CHARS   = 8000         # justification, etc.
MAX_NAME_CHARS   = 256          # serviceName, quotaName
MAX_REGIONS      = 50           # max regions per submit
MAX_ATTACHMENTS  = 3            # Support API allows 3 attachments
MAX_ATTACH_BYTES = 5 * 1024 * 1024  # 5 MB total per attachment set (Support API limit)
VALID_ACTIONS    = {'submit', 'lookup', 'list-quotas', 'list-services', 'list-regions'}
VALID_URGENCY    = {'low', 'normal', 'high'}
RE_SERVICE       = re.compile(r'^[a-z0-9-]{1,64}$')
RE_QUOTA_CODE    = re.compile(r'^L-[A-Za-z0-9]{8}$')
RE_ITEM_CODE     = re.compile(r'^[a-z0-9-]{1,128}$')
RE_REGION        = re.compile(r'^[a-z]{2}-[a-z]+-\d{1,2}$')
RE_FILENAME      = re.compile(r'^[A-Za-z0-9_.\- ]{1,200}$')   # no path separators

class BadInput(Exception): pass

def _validate(body):
  """Sanity-check input fields. Raises BadInput on validation failure."""
  if not isinstance(body, dict): raise BadInput('body must be an object')
  a = body.get('action', 'submit')
  if a not in VALID_ACTIONS: raise BadInput(f'unknown action: {a!r}')
  for k in ('service', 'itemCode'):
    v = body.get(k, '')
    if v and (not isinstance(v, str) or not (RE_SERVICE if k=='service' else RE_ITEM_CODE).match(v)):
      raise BadInput(f'{k}: invalid format')
  qc = body.get('quotaCode', '')
  if qc and (not isinstance(qc, str) or not RE_QUOTA_CODE.match(qc)):
    raise BadInput('quotaCode: must match L-XXXXXXXX')
  r = body.get('region', '')
  if r and (not isinstance(r, str) or not RE_REGION.match(r)):
    raise BadInput('region: invalid format')
  rs = body.get('regions', None)
  if rs is not None:
    # 'regions' for list-quotas is a list[str]; for submit it's a dict[region->desired]
    if isinstance(rs, list):
      if len(rs) > MAX_REGIONS: raise BadInput('regions: too many')
      for x in rs:
        if not isinstance(x, str) or not RE_REGION.match(x): raise BadInput('regions: bad entry')
    elif isinstance(rs, dict):
      if len(rs) > MAX_REGIONS: raise BadInput('regions: too many')
      for k, v in rs.items():
        if not isinstance(k, str) or not RE_REGION.match(k): raise BadInput(f'regions[{k}]: bad key')
        if not isinstance(v, (int, float, str)) or len(str(v)) > 64: raise BadInput(f'regions[{k}]: bad value')
    else:
      raise BadInput('regions: must be list or dict')
  for k in ('serviceName', 'quotaName'):
    v = body.get(k, '')
    if v and (not isinstance(v, str) or len(v) > MAX_NAME_CHARS):
      raise BadInput(f'{k}: too long (>{MAX_NAME_CHARS})')
  j = body.get('justification', '')
  if j and (not isinstance(j, str) or len(j) > MAX_TEXT_CHARS):
    raise BadInput(f'justification: too long (>{MAX_TEXT_CHARS})')
  u = body.get('urgency', 'normal')
  if u not in VALID_URGENCY: raise BadInput('urgency: must be low/normal/high')
  atts = body.get('attachments', [])
  if atts:
    if not isinstance(atts, list) or len(atts) > MAX_ATTACHMENTS:
      raise BadInput(f'attachments: max {MAX_ATTACHMENTS}')
    total = 0
    for a in atts:
      if not isinstance(a, dict) or 'fileName' not in a or 'data' not in a:
        raise BadInput('attachments: each must have fileName and data')
      if not isinstance(a['fileName'], str) or not RE_FILENAME.match(a['fileName']):
        raise BadInput('attachments.fileName: invalid (no path separators, max 200 chars)')
      if not isinstance(a['data'], str): raise BadInput('attachments.data: must be base64 string')
      # Approximate decoded size from base64 length
      total += (len(a['data']) * 3) // 4
      if total > MAX_ATTACH_BYTES:
        raise BadInput(f'attachments: total decoded size exceeds {MAX_ATTACH_BYTES} bytes')


# CTI routing map. Maps AWS service-quotas ServiceCode to the SLI categoryCode
# (the Support API itemCode) that native Service Quotas uses for that service.
#
# Generated from analysis of historical native Service Quotas limit-increase support cases.
# 76 single-itemCode services + 4 services (ec2, ses, sms-voice, vpc) that split across
# multiple itemCodes based on quota name.
#
# Regenerated periodically from analysis of historical Service Quotas support cases.
# CTI map embedded at build time from quota_cti_map.json
_CTI_MAP = {"version":"2.0","simple_map":{"AWSCloudMap":"service-code-cloud-map","access-analyzer":"service-code-iam-access-analyzer","acm":"acm-limits","acm-pca":"certificate-manager-private-certificate-authority-ca","amplify":"service-code-aws-amplify","apigateway":"api-gateway-limits","appconfig":"service-code-appconfig","appflow":"service-code-appflow","application-autoscaling":"application-auto-scaling-limits","appmesh":"service-code-app-mesh","apprunner":"service-code-apprunner","appstream2":"appstream2","appsync":"service-code-appsync","aps":"service-code-managed-service-for-prometheus","athena":"athena-limits","autoscaling":"autoscaling-limits","backup":"service-code-backup","bedrock":"service-code-bedrock","cassandra":"service-code-keyspaces-for-apache-cassandra","chime":"service-code-chime","cleanrooms":"service-code-clean-rooms","cloudformation":"cloudformation-stacks","cloudfront":"cloudfront-distributions","cloudhsm":"cloudhsm-limits","cloudwatch":"cloudwatch-limits","codeartifact":"service-code-codeartifact","codebuild":"codebuild-limits","codecommit":"service-code-codecommit","cognito-idp":"amazon-congnito-limits","comprehend":"service-code-comprehend","connect":"connect-limits","crowdscale-usagelimitservice":"service-code-mechanical-turk","datasync":"service-code-aws-datasync","devicefarm":"service-code-device-farm","dms":"dms-limits","docdb":"service-code-documentdb","ds":"directory-service-limits","dynamodb":"dynamodb-limits","ebs":"ebs-volumes","ec2-ipam":"service-code-vpc-ip-address-manager","ec2fastlaunch":"service-code-ec2-fast-launch","ecr":"container-registry-limits","ecs":"container-services-limit","eks":"service-code-eks","elasticache":"elasticache-nodes","elasticbeanstalk":"elastic-beanstalk-limits","elasticloadbalancing":"elastic-load-balancers","elasticmapreduce":"service-code-emr","emr-serverless":"service-code-emr","es":"service-code-opensearch-service-successor-to-amazon-elasticsearch-service","events":"cloudwatch-events-limits","fargate":"service-code-fargate","firehose":"kinesis-firehose-limits","fms":"service-code-firewall-manager","fsx":"service-code-fsx-for-lustre","gamelift":"gamelift-limits","geo":"service-code-location-service","globalaccelerator":"service-code-global-accelerator","glue":"service-code-glue","groundstation":"service-code-ground-station","iam":"iam-groups-and-users","imagebuilder":"service-code-ec2-image-builder","iot":"service-code-iot-core","iotcore":"service-code-iot-core","iotfleetwise":"service-code-iot-fleetwise","iotwireless":"service-code-iot-wireless","ivs":"service-code-interactive-video-service","ivschat":"service-code-interactive-video-service-chat","kafkaconnect":"service-code-amazon-managed-streaming-for-kafka","kendra":"service-code-kendra","kinesis":"kinesis-limits","kinesisanalytics":"kinesis-analytics-limits","kinesisvideo":"service-code-kinesis-video-streams","kms":"aws-key-management-service-limits","lambda":"aws-lambda-limits","lightsail":"lightsail-limits","logs":"cloudwatch-logs-limits","mediaconnect":"service-code-aws-elemental-mediaconnect","mediaconvert":"service-code-mediaconvert","medialive":"service-code-medialive","mediapackage":"service-code-mediapackage","monitoring":"cloudwatch-limits","neptune":"service-code-neptune","network-firewall":"service-code-network-firewall","omics":"service-code-omics","organizations":"aws-organizations","outposts":"service-code-outposts","personalize":"service-code-personalize","polly":"service-code-polly","ram":"service-code-aws-resource-acess-manager","rds":"rds-instances","redshift":"redshift-limit-increases","rekognition":"rekognition","resiliencehub":"service-code-resilience-hub","rolesanywhere":"service-code-iam-roles-anywhere","route53":"route-53-limits","route53resolver":"service-code-route-53-resolver","s3":"simple-storage-service-limit","sagemaker":"service-code-sagemaker-endpoints","scheduler":"service-code-eventbridge-scheduler","schemas":"service-code-eventbridge","servicecatalog":"service-catalog-limits","servicequotas":"service-limit-increase","shield":"shield-limits","sqs":"sns-limits","ssm":"service-code-ec2-systems-manager","sso":"service-code-single-sign-on","states":"step-functions","sts":"iam-groups-and-users","swf":"swf-limits","textract":"service-code-textract","transcribe":"service-code-transcribe","translate":"service-code-translate","vpc-lattice":"service-code-vpc-lattice","wafv2":"waf-limits","workspaces":"workspaces-limits","workspaces-web":"service-code-workspaces-web"},"keyword_rules":{"ec2":[{"keyword_quota_name":"ec2-vpc elastic ip","itemCode":"elastic-ips"},{"keyword_quota_name":"elastic ip","itemCode":"elastic-ips"},{"keyword_quota_name":"running spot","itemCode":"ec2-spot-instances"},{"keyword_quota_name":"spot instance","itemCode":"ec2-spot-instances"},{"keyword_quota_name":"running dedicated","itemCode":"ec2-dedicated-hosts-limits"},{"keyword_quota_name":"dedicated host","itemCode":"ec2-dedicated-hosts-limits"},{"keyword_quota_name":"reserved","itemCode":"ec2-reserved-purchase-instances"},{"keyword_quota_name":"capacity block","itemCode":"service-code-ec2-capacity-blocks"},{"keyword_quota_name":"*","itemCode":"ec2-instances"}],"ses":[{"keyword_quota_name":"production access","itemCode":"ses-production-access"},{"keyword_quota_name":"sandbox","itemCode":"ses-production-access"},{"keyword_quota_name":"dedicated ip","itemCode":"ses-production-access"},{"keyword_quota_name":"*","itemCode":"service-code-ses"}],"sms-voice":[{"keyword_quota_name":"voice production","itemCode":"pinpoint-voice"},{"keyword_quota_name":"voice sandbox","itemCode":"pinpoint-voice"},{"keyword_quota_name":"*","itemCode":"service-code-pinpoint-sms"}],"sns":[{"keyword_quota_name":"sms","itemCode":"service-code-sns-text-messaging"},{"keyword_quota_name":"text message","itemCode":"service-code-sns-text-messaging"},{"keyword_quota_name":"*","itemCode":"sns-limits"}],"vpc":[{"keyword_quota_name":"transit gateway","itemCode":"service-code-vpc-transit-gateway"},{"keyword_quota_name":"ipam","itemCode":"service-code-vpc-ip-address-manager"},{"keyword_quota_name":"*","itemCode":"vpc-limits"}]},"item_canonical_names":{"service-code-eks":"Amazon Elastic Kubernetes Service (Amazon EKS)","service-code-amazon-managed-streaming-for-kafka":"Managed Streaming for Kafka Connect","service-code-mediaconvert":"AWS Elemental MediaConvert","service-code-clean-rooms":"AWS Clean Rooms","service-code-codeartifact":"AWS CodeArtifact","service-code-comprehend":"Amazon Comprehend","service-code-location-service":"Amazon Location Service (Amazon Location)","service-code-apprunner":"AWS App Runner","service-code-neptune":"Amazon Neptune","service-code-kendra":"Amazon Kendra","gamelift-limits":"Amazon GameLift Servers","application-auto-scaling-limits":"Application Auto Scaling (Other than EC2 ASGs)","kinesis-firehose-limits":"Amazon Kinesis Data Firehose","redshift-limit-increases":"Amazon Redshift","swf-limits":"Amazon Simple Workflow Service","service-code-aws-datasync":"AWS DataSync","service-code-iot-fleetwise":"AWS IoT FleetWise","service-code-appflow":"Amazon AppFlow","service-code-cloud-map":"AWS Cloud Map","service-code-route-53-resolver":"Route 53 Resolver","service-code-kinesis-video-streams":"Amazon Kinesis Video Streams","service-code-documentdb":"Amazon DocumentDB (with MongoDB compatibility)","service-code-polly":"Amazon Polly","service-code-single-sign-on":"AWS IAM Identity Center (successor to AWS Single Sign-On)","service-code-firewall-manager":"AWS Firewall Manager","service-code-omics":"AWS HealthOmics","service-code-aws-elemental-mediaconnect":"AWS Elemental MediaConnect","elastic-beanstalk-limits":"AWS Elastic Beanstalk","service-code-vpc-ip-address-manager":"IPAM","service-code-eventbridge-scheduler":"Amazon EventBridge Scheduler","service-code-managed-service-for-prometheus":"Amazon Managed Prometheus","service-code-aws-resource-acess-manager":"AWS Resource Access Manager","service-code-eventbridge":"Amazon EventBridge Schema Registry","service-code-personalize":"Amazon Personalize","service-code-ec2-image-builder":"EC2 Image Builder","directory-service-limits":"AWS Directory Service","service-code-opensearch-service-successor-to-amazon-elasticsearch-service":"Amazon OpenSearch Service","shield-limits":"AWS Shield Advanced","step-functions":"AWS Step Functions","service-code-outposts":"AWS Outposts","service-code-keyspaces-for-apache-cassandra":"Amazon Keyspaces (for Apache Cassandra)","service-catalog-limits":"AWS Service Catalog","service-code-resilience-hub":"AWS Resilience Hub","kinesis-analytics-limits":"Amazon Managed Service for Apache Flink","service-code-chime":"Amazon Chime","service-code-mediapackage":"AWS Elemental MediaPackage","service-code-network-firewall":"AWS Network Firewall","cloudhsm-limits":"AWS CloudHSM","service-code-global-accelerator":"AWS Global Accelerator","service-code-interactive-video-service-chat":"Amazon Interactive Video Service Chat","service-code-workspaces-web":"Amazon WorkSpaces Secure Browser","waf-limits":"AWS WAF","kinesis-limits":"Amazon Kinesis Data Streams","cloudformation-stacks":"AWS CloudFormation","service-code-iot-wireless":"AWS IoT Wireless","service-code-medialive":"AWS Elemental MediaLive","service-code-appsync":"AWS AppSync","aws-key-management-service-limits":"AWS Key Management Service (AWS KMS)","service-code-device-farm":"AWS Device Farm","service-code-backup":"AWS Backup","service-code-transcribe":"Amazon Transcribe","service-code-vpc-transit-gateway":"VPC - Transit Gateway","service-code-iot-core":"AWS IoT Core","service-code-codecommit":"AWS CodeCommit","autoscaling-limits":"Auto Scaling","cloudwatch-logs-limits":"Amazon CloudWatch Logs","rekognition":"Amazon Rekognition","service-code-ec2-fast-launch":"EC2 Fast Launch","service-code-iam-access-analyzer":"Access Analyzer","pinpoint-voice":"AWS End User Messaging Voice (Pinpoint)","service-code-iam-roles-anywhere":"IAM Roles Anywhere","service-code-vpc-lattice":"VPC Lattice","service-code-ec2-systems-manager":"AWS Systems Manager","elasticache-nodes":"Amazon ElastiCache","simple-storage-service-limit":"Amazon Simple Storage Service (Amazon S3)","service-code-appconfig":"AWS AppConfig","service-code-ec2-capacity-blocks":"EC2 Capacity Blocks","service-code-aws-amplify":"AWS Amplify","amazon-congnito-limits":"Amazon Cognito User Pools","dms-limits":"AWS Database Migration Service (AWS DMS)","service-code-sns-text-messaging":"SES Service Limits","ses-production-access":"SES Service Limits","container-services-limit":"Amazon Elastic Container Service (Amazon ECS)","container-registry-limits":"Amazon Elastic Container Registry (Amazon ECR)","service-code-app-mesh":"AWS App Mesh","workspaces-limits":"Amazon WorkSpaces","route-53-limits":"Amazon Route 53","service-code-interactive-video-service":"Amazon Interactive Video Service","service-code-translate":"Amazon Translate","ec2-reserved-purchase-instances":"EC2 Reserved Instance Purchase Instances","service-code-mechanical-turk":"Mechanical Turk","service-code-glue":"AWS Glue","aws-organizations":"AWS Organizations","codebuild-limits":"AWS CodeBuild","service-code-textract":"Amazon Textract","elastic-ips":"Elastic IPs","certificate-manager-private-certificate-authority-ca":"AWS Private Certificate Authority","service-code-emr":"Amazon EMR Serverless","elastic-load-balancers":"Elastic Load Balancing (ELB)","service-code-fargate":"AWS Fargate","lightsail-limits":"Amazon Lightsail","cloudfront-distributions":"Amazon CloudFront","rds-instances":"Amazon Relational Database Service (Amazon RDS)","api-gateway-limits":"Amazon API Gateway","cloudwatch-limits":"Amazon CloudWatch","appstream2":"Amazon WorkSpaces Applications","athena-limits":"Amazon Athena","iam-groups-and-users":"AWS Identity and Access Management (IAM)","connect-limits":"Amazon Connect","service-code-fsx-for-lustre":"Amazon FSx","ebs-volumes":"Amazon Elastic Block Store (Amazon EBS)","service-code-ground-station":"AWS Ground Station","cloudwatch-events-limits":"Amazon EventBridge (CloudWatch Events)","ec2-dedicated-hosts-limits":"EC2 Dedicated Hosts","service-code-ses":"Amazon Simple Email Service(Amazon SES)","acm-limits":"AWS Certificate Manager (ACM)","service-code-sagemaker-endpoints":"Amazon SageMaker","vpc-limits":"VPC","service-code-pinpoint-sms":"AWS End User Messaging SMS (Pinpoint)","sns-limits":"Amazon Simple Notification Service (Amazon SNS)","aws-lambda-limits":"AWS Lambda","service-code-bedrock":"Amazon Bedrock","ec2-spot-instances":"EC2 Spot Instances","ec2-instances":"EC2 Instances","dynamodb-limits":"DynamoDB"},"fallback":"service-limit-increase"}

FALLBACK_CATEGORY = _CTI_MAP.get('fallback', 'service-limit-increase')
_KNOWN_ITEM_CODES = (
    set(_CTI_MAP.get('simple_map', {}).values())
    | {r['itemCode'] for rules in _CTI_MAP.get('keyword_rules', {}).values() for r in rules}
    | set(_CTI_MAP.get('item_canonical_names', {}).keys())
)


def _resolve_category_code(service_code, quota_code, quota_name, item_code='', service_name=''):
  """Resolve the Support API categoryCode (the Support API itemCode) for routing
  to the correct service team. Matches the behavior of native Service Quotas console.

  Resolution priority:
    1. Keyword rules for this service (if service has multi-itemCode split) — match
       against quota_name. '*' keyword is the service-wide default.
    2. Simple map lookup — for services where all quotas route to one itemCode.
    3. Runtime fallback via item_canonical_names — match service_name/service_code
       against observed SLI category names. Handles services not in the simple map.
    4. Frontend-supplied item_code if it looks like a known routing code.
    5. Legacy fuzzy match on service_code (safety net for near-miss mappings).
    6. Fallback to 'service-limit-increase' (generic catch-all).
  """
  if not service_code:
    return FALLBACK_CATEGORY

  svc = service_code.lower().strip()
  qname = (quota_name or '').lower().strip()
  sname = (service_name or '').lower().strip()

  # 1. Keyword rules for multi-itemCode services
  if svc in _CTI_MAP.get('keyword_rules', {}):
    rules = _CTI_MAP['keyword_rules'][svc]
    default_item = None
    for rule in rules:
      kw = rule.get('keyword_quota_name', rule.get('keyword', '')).lower()
      if kw == '*':
        default_item = rule['itemCode']
        continue
      if kw and kw in qname:
        print(f'CTI resolve: svc={svc!r} quota={qname!r} matched rule {kw!r} -> {rule["itemCode"]}')
        return rule['itemCode']
    if default_item:
      print(f'CTI resolve: svc={svc!r} quota={qname!r} used default -> {default_item}')
      return default_item

  # 2. Simple map — service has one itemCode for all its quotas
  if svc in _CTI_MAP.get('simple_map', {}):
    item = _CTI_MAP['simple_map'][svc]
    print(f'CTI resolve: svc={svc!r} simple-map -> {item}')
    return item

  # 3. Runtime fallback: match service_name against canonical SLI names.
  # item_canonical_names maps itemCode -> representative SLI display name.
  # STRICT matching: exact equality, OR both token-sets equal, OR subset with 2+ signals.
  canonical = _CTI_MAP.get('item_canonical_names', {})
  if canonical and sname:
    import re as _re
    def _norm(s):
      n = _re.sub(r'[^a-z0-9]+', ' ', s.lower()).strip()
      for prefix in ('amazon ', 'aws '):
        if n.startswith(prefix):
          n = n[len(prefix):]
      return n
    sname_norm = _norm(sname)
    DROP_TOKENS = {'service', 'services', 'limits', 'limit', 'amazon', 'aws', 'for', 'the', 'by', 'and'}
    sname_tokens = set(sname_norm.split())
    sname_sig = {t for t in sname_tokens if t not in DROP_TOKENS and len(t) >= 3}
    best_match = None
    best_score = 0
    if sname_sig:
      for item, cname in canonical.items():
        cname_norm = _norm(cname)
        if not cname_norm or len(cname_norm) < 5: continue
        if cname_norm in ('service quotas', 'general', 'other'): continue
        cname_tokens = set(cname_norm.split())
        cname_sig = {t for t in cname_tokens if t not in DROP_TOKENS and len(t) >= 3}
        if not cname_sig: continue
        score = 0
        if sname_norm == cname_norm:
          score = 1000
        elif sname_sig == cname_sig:
          score = 500
        elif cname_sig <= sname_sig and len(cname_sig) >= 1:
          # ALL canonical tokens present in service name — high confidence
          # (e.g., "Amazon Connect Cases" contains canonical "Amazon Connect")
          score = 100 + sum(len(t) for t in cname_sig)
        elif sname_sig <= cname_sig and len(sname_sig) >= 2:
          # All service-name tokens present in canonical, but require 2+ shared tokens
          # to avoid single-word weak matches like "AWS Private 5G" matching "Private CA"
          score = 100 + sum(len(t) for t in sname_sig)
        if score > best_score:
          best_score = score
          best_match = item
    if best_match and best_score >= 100:
      print(f'CTI resolve: svc={svc!r} name={sname!r} fallback-by-canonical-name -> {best_match} (score {best_score})')
      return best_match

  # 4. Frontend-supplied item_code — only honored if it is a KNOWN routing code.
  #    Never trust an arbitrary client-supplied categoryCode for case routing (L-1).
  if item_code and item_code in _KNOWN_ITEM_CODES:
    print(f'CTI resolve: svc={svc!r} using known frontend itemCode -> {item_code}')
    return item_code

  # 5. Legacy fuzzy fallback — word-boundary substring match against known simple_map keys.
  #    Requires both svc and known_svc to be at least 4 chars AND the shorter one to appear
  #    as a whole token (word-boundary) in the longer one. Rejects 'config' → 'appconfig'.
  def _tokenize(s):
    return set(re.sub(r'[^a-z0-9]+', ' ', s.lower()).split()) if s else set()
  svc_tokens_for_fuzzy = _tokenize(svc)
  for known_svc, item in _CTI_MAP.get('simple_map', {}).items():
    if len(svc) < 4 or len(known_svc) < 4: continue
    known_tokens = _tokenize(known_svc)
    if svc == known_svc:
      print(f'CTI resolve: svc={svc!r} fuzzy-exact -> {item}')
      return item
    # Only accept if they share a token (not just substring) — avoids kafka→kafkaconnect
    common = svc_tokens_for_fuzzy & known_tokens
    common_sig = {t for t in common if len(t) >= 4}
    if common_sig:
      print(f'CTI resolve: svc={svc!r} fuzzy-token -> {known_svc!r} = {item}')
      return item

  # 6. Final fallback
  print(f'CTI resolve: svc={svc!r} no match, using fallback -> {FALLBACK_CATEGORY}')
  return FALLBACK_CATEGORY


def handler(event, context):
  if event.get('httpMethod') == 'OPTIONS':
    return {'statusCode': 200, 'headers': HEADERS, 'body': ''}
  raw = event.get('body') or ''
  if len(raw) > MAX_BODY_BYTES:
    return {'statusCode': 413, 'headers': HEADERS, 'body': json.dumps({'error': 'request too large'})}
  try:
    body = json.loads(raw)
    _validate(body)
  except json.JSONDecodeError:
    return {'statusCode': 400, 'headers': HEADERS, 'body': json.dumps({'error': 'invalid JSON'})}
  except BadInput as e:
    return {'statusCode': 400, 'headers': HEADERS, 'body': json.dumps({'error': str(e)})}
  action = body.get('action', 'submit')
  if action == 'lookup':
    return lookup_quotas(body)
  if action == 'list-quotas':
    return list_service_quotas(body)
  if action == 'list-services':
    return list_services(body)
  if action == 'list-regions':
    return list_regions()
  return submit_request(body)

def list_regions():
  ec2 = boto3.client('ec2', region_name='us-east-1')
  regions = [r['RegionName'] for r in ec2.describe_regions(AllRegions=False)['Regions']]
  regions.sort()
  return {'statusCode': 200, 'headers': HEADERS, 'body': json.dumps({'regions': regions})}

def list_services(body):
  region = body.get('region', 'us-east-1')
  sq = boto3.client('service-quotas', region_name=region)
  services = []
  paginator = sq.get_paginator('list_services')
  for page in paginator.paginate():
    for s in page['Services']:
      services.append({'code': s['ServiceCode'], 'name': s['ServiceName']})
  services.sort(key=lambda x: x['name'])
  return {'statusCode': 200, 'headers': HEADERS, 'body': json.dumps({'services': services})}

def list_service_quotas(body):
  """Return the full catalog by merging AWS defaults with applied (account-specific) values.
  list_service_quotas alone only returns quotas with an applied value (i.e. the user has
  previously requested a change or AWS has set a per-account value). That leaves out all
  the still-at-default quotas. list_aws_default_service_quotas is the authoritative full
  catalog. We merge both, preferring the applied value where it exists."""
  svc = body['service']
  region = body.get('region', 'us-east-1')
  sq = boto3.client('service-quotas', region_name=region)

  quotas_by_code = {}
  try:
    paginator = sq.get_paginator('list_aws_default_service_quotas')
    for page in paginator.paginate(ServiceCode=svc):
      for q in page['Quotas']:
        quotas_by_code[q['QuotaCode']] = {
          'code': q['QuotaCode'],
          'name': q['QuotaName'],
          'default': q.get('Value', 0),
          'applied': q.get('Value', 0),
          'adjustable': q.get('Adjustable', False),
          'unit': q.get('Unit', 'None'),
          'global': q.get('GlobalQuota', False),
        }
  except Exception as e:
    print(f'list_aws_default_service_quotas failed for {svc}/{region}: {e}')

  try:
    paginator = sq.get_paginator('list_service_quotas')
    for page in paginator.paginate(ServiceCode=svc):
      for q in page['Quotas']:
        code = q['QuotaCode']
        existing = quotas_by_code.get(code, {})
        quotas_by_code[code] = {
          'code': code,
          'name': q['QuotaName'],
          'default': existing.get('default', q.get('DefaultValue', q.get('Value', 0))),
          'applied': q.get('Value', existing.get('applied', 0)),
          'adjustable': q.get('Adjustable', existing.get('adjustable', False)),
          'unit': q.get('Unit', existing.get('unit', 'None')),
          'global': q.get('GlobalQuota', existing.get('global', False)),
        }
  except Exception as e:
    print(f'list_service_quotas failed for {svc}/{region}: {e}')

  quotas = sorted(quotas_by_code.values(), key=lambda x: x['name'])
  return {'statusCode': 200, 'headers': HEADERS, 'body': json.dumps({'quotas': quotas})}

def lookup_quotas(body):
  missing = [f for f in ('service', 'regions', 'quotaCode') if not body.get(f)]
  if missing:
    return {'statusCode': 400, 'headers': HEADERS,
            'body': json.dumps({'error': f'missing required field(s): {", ".join(missing)}'})}
  svc = body['service']
  regions = body['regions']
  quota_code = body['quotaCode']
  results = {}
  for r in regions:
    try:
      sq = boto3.client('service-quotas', region_name=r)
      try:
        resp = sq.get_service_quota(ServiceCode=svc, QuotaCode=quota_code)
        results[r] = resp['Quota']['Value']
      except Exception:
        resp = sq.get_aws_default_service_quota(ServiceCode=svc, QuotaCode=quota_code)
        results[r] = resp['Quota']['Value']
    except Exception as e:
      # Log detail server-side; never return upstream exception text to the caller
      # (AWS authorization errors embed account IDs / assumed-role ARNs).
      print(f'lookup_quotas: region={r} svc={svc} quota={quota_code} failed: {type(e).__name__}: {str(e)[:200]}')
      results[r] = 'error: lookup failed'
  return {'statusCode': 200, 'headers': HEADERS, 'body': json.dumps({'quotas': results})}

def _oneline(s):
  # Replace control chars (CR/LF/tab/etc.) with spaces so user-supplied values can't
  # inject extra lines into the structured case body or a multi-line subject (L-2).
  return ''.join(ch if ' ' <= ch != chr(127) else ' ' for ch in str(s)).strip()


def submit_request(body):
  """Create one consolidated support case matching the automated Service Quotas CTI format."""
  missing = [f for f in ('serviceName', 'quotaCode', 'quotaName', 'regions', 'justification')
             if not body.get(f)]
  if missing:
    return {'statusCode': 400, 'headers': HEADERS,
            'body': json.dumps({'error': f'missing required field(s): {", ".join(missing)}'})}
  svc_name = body['serviceName']
  svc_code = body.get('service', '')
  item_code = body.get('itemCode', '')
  quota_code = body['quotaCode']
  quota_name = body['quotaName']
  regions = body['regions']  # {region: desired_value}
  justification = body['justification']
  urgency = body.get('urgency', 'normal')

  sev = 'low' if urgency == 'normal' else 'normal' if urgency == 'high' else 'urgent'

  # Resolve the categoryCode (the Support API itemCode) to route to the correct service team.
  category_code = _resolve_category_code(svc_code, quota_code, quota_name, item_code, svc_name)

  # Build body matching native Service Quotas case format — same structure as
  # what the Service Quotas console produces, so internal tooling parses it the same way.
  lines = [f'Service: {_oneline(svc_name)}', f'Quota: {_oneline(quota_name)} ({quota_code})', '']
  lines.append('Requested increases:')
  for region, desired in regions.items():
    lines.append(f'  Region: {_oneline(region)} - Desired value: {_oneline(str(desired))}')
  lines.append('')
  lines.append('--- Justification ---')
  lines.append(justification)

  try:
    support = boto3.client('support', region_name='us-east-1')

    attachment_set_id = None
    attachments = body.get('attachments', [])
    if attachments:
      import base64
      att_list = []
      for att in attachments:
        att_list.append({
          'fileName': att['fileName'],
          'data': base64.b64decode(att['data'])
        })
      att_resp = support.add_attachments_to_set(attachments=att_list)
      attachment_set_id = att_resp['attachmentSetId']

    create_args = dict(
      subject=f'Quota Increase: {_oneline(svc_name)} - {_oneline(quota_name)}',
      communicationBody='\n'.join(lines),
      serviceCode='service-limit-increase',
      categoryCode=category_code,
      issueType='service-limit-increase',
      severityCode=sev,
      ccEmailAddresses=[]
    )
    if attachment_set_id:
      create_args['attachmentSetId'] = attachment_set_id

    resp = support.create_case(**create_args)
    case_id_long = resp['caseId']  # internal form: case-<acct>-<year>-<hex>

    # support.create_case returns the long-form caseId. Customers expect the
    # short numeric displayId (e.g., 1XXXXXXXXXXXXXX) which is what shows up in
    # AWS Support Center. Fetch displayId via describe_cases. Falls back to the
    # long caseId if describe_cases is unavailable (Basic-tier accounts) or the
    # case isn't indexed yet.
    import time
    display_id = None
    for attempt in range(6):
      try:
        desc = support.describe_cases(caseIdList=[case_id_long], language='en', includeResolvedCases=True)
        cases = desc.get('cases', [])
        if cases:
          display_id = cases[0].get('displayId')
          if display_id:
            break
      except Exception as e:
        msg = str(e)
        if 'SubscriptionRequired' in msg or 'AccessDenied' in msg:
          print(f'describe_cases not available ({type(e).__name__}); using long caseId for display.')
          break
        print(f'describe_cases attempt {attempt} transient error: {msg[:120]}')
      time.sleep(0.5)

    public_case_id = display_id or case_id_long
    case_url = f'https://console.aws.amazon.com/support/home#/case/?displayId={public_case_id}'
    return {'statusCode': 200, 'headers': HEADERS, 'body': json.dumps({
      'results': {r: {'status': 'case_created', 'caseId': public_case_id, 'caseUrl': case_url} for r in regions},
      'consolidatedCaseId': public_case_id,
      'caseId': public_case_id,
      'internalCaseId': case_id_long,
      'caseUrl': case_url,
      'categoryCode': category_code
    })}
  except Exception as e:
    # Log detail server-side (never return upstream exception text — it can embed
    # the account ID / assumed-role ARN). Return 500 so the Api5XXAlarm fires.
    print(f'submit_request failed: {type(e).__name__}: {str(e)[:300]}')
    return {'statusCode': 500, 'headers': HEADERS, 'body': json.dumps({
      'error': 'Failed to create the support case. Please retry; if the problem persists, contact your account administrator.',
    })}
