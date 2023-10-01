
<div align="center">
 <p>
  <h1>
    Dredge
  </h1>
 </p>
</div>

<div align="left">
  <h3>
   :zap:Log collection, tactical analysis, and rapid response in the cloud... pa' la hinchada:zap:
  </h3>
</div>


---
### TL;DR
- It's still a work in progress
- You can obtain logs from AWS (ALB, WAF, CloudTrail, EventHistory, VPC Flow Logs), GCP, Github, Kubernetes among others.
- Incident Response: You can disable user access keys, network isolate ec2 instances, make s3 buckets private, among others.
- Threat Hunting: VirusTotal and Shodan Integration, get attacks from api calls.
- Cloud Status: You can get tactical data from the cloud tenants, list users, servers, buckets, etc.

---
<div align="justify">
<p>Dredge is a tool designed to identify and respond quickly to an attack in cloud environments, particularly when one is not adequately prepared.</p>

<p>With Dredge, you can quickly gather logs from Cloud Providers and SaaS services such as AWS, Azure, Github, etc. It is intended to abstract forensic analysts from the specific technical knowledge of Cloud environments, allowing for a rapid response in the event of an attack.</p>

<p>It is also equipped with a set of detection rules that enable the analysis of collected events in search of TTPs (Tactics, Techniques, and Procedures) or IoCs (Indicators of Compromise) in a practical and user-friendly manner. </p>
</div>

---
### :mag: [Log Collection](https://github.com/solidarity-labs/dredge#mag-log-collection-1) 
  - AWS - EventHistory
  - AWS - Guardduty
  - AWS - Cloudtrail (S3)
  - AWS - VPC Flow Logs (S3)
  - AWS - Load Balancer (S3)
  - AWS - WAF Logs (S3)
  - Github - Audit Logs
  - Kubernetes - Logs
  - Kubernetes - Pod Logs

### :thought_balloon: [Cloud Status](https://github.com/solidarity-labs/dredge#thought_balloon-cloud-status-1) 
  - AWS - IAM User List
  - AWS - IAM Access Keys 
  - AWS - Lambda Functions
  - AWS - EC2 instance data
  - AWS - RDS 
  - AWS - EKS
  - AWS - S3 Buckets, public buckets and public objects
  - GCP - API Logs
  - Github - Audit Log

### :dart: [Threat Hunting](https://github.com/solidarity-labs/dredge#dart-threat-hunting-1)
  - IoC (Indicators of Compromise) search.
  - Custom rules creation.
  - Shodan Integration
  - VirusTotal Integration
  - AWS API Call Timeline creation
  - AWS Threat Hunt (IP, IAM User or Access Key Id)
  - Dangerous AWS API Calls Hunt.

### :boom: [Incident Response](https://github.com/solidarity-labs/dredge#boom-incident-response-1)
  - AWS - Delete IAM User
  - AWS - Disable AccessKey
  - AWS - Remove Logging Profile
  - AWS - Network Isolate EC2 Instance
  - AWS - Get Forensic Image from EC2 instance volume
  - AWS - Get Lambda env vars
  - AWS - Make a bucket private
  - AWS - Make an object private
  
---
## Setup
1. Clone the repo
2. Install python3 requirements

```bash
pip3 install -r requirements.txt
```

3. Use your Cloud Provider credentials: [AWS](https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html) | [GCP](https://cloud.google.com/docs/authentication/provide-credentials-adc#how-to)

Example with AWS credentials (in the ~/.aws/credentials file).

```yaml
[dredge]
aws_access_key_id = AKIAQDALEOESTEDALEOE
aws_secret_access_key = +SARASASSA/SARASDANA/SARANtRC
```
4. Start!
```bash
python3 dredge.py --help
```

---
## How to Use: Config File
1. Specify <b>dates</b>, keeping in mind that EventHistory logs can take a long time to retrieve. Try to be specific.
```yaml
configs:
  start_date: '2023-01-01'
  end_date: '2023-06-1'
```

2. Define the <b>aws configs</b>:
- Profile_region is the profile for aws authentication
- Regions are those needed for log retrieve if multy region strategy is in place. 
- You can specify multiple profiles to get logs from different accounts.

```yaml
aws_configs:
  profiles: ['default']
  profile_region: 'us-east-1'
  regions: ['us-east-1']
```

3. Configure the config file. 
- Set <b>"enabled: True"</b> for the log sources you want to analyze. 
- For logs stored in S3 buckets (LB | WAF | VPC | CLOUDTRAIL) you must specify the bucket name.

```yaml
  event_history:
    enabled: False
    threat_hunting: False
  guardduty:
    enabled: False
  lb:
    enabled: False
    buckets: ['alb-logs-*-test']
```

4. For Github logs, you need to specify:
- Organization or Enterprise name
- Access Token
- Set <b>Enabled True</b>

```yaml
github_configs:
  enabled: True
  access_token: ''
  org_name: []
  ent_name: ['*-enterprise']
```

5. Execution:

```bash
# Getting logs from config
python3 dredge.py co --file config.yaml

```
[![asciicast](https://asciinema.org/a/VjWMuCoyRt1aWhiltHYnmdFqw.svg)](https://asciinema.org/a/VjWMuCoyRt1aWhiltHYnmdFqw)


### Full Config file example

```yaml
configs:
  start_date: '2023-09-29'
  end_date: '2023-09-30'
  destination_folder: 'logs_dredge'
  output_file: 'test1'
  shodan_api_key: '9R6Y860tl9q--------------------------'
  vt_api_key: '5294a7d0ff16------------------046aa2528dc0a4205'

gcp_configs:
  enabled: False
  cred_files: ['logtesting-.json']

aws_configs:
  enabled: False
  profiles: ['demo-env']
  profile_region: 'us-east-1'
  regions: ['us-east-1']

  event_history:
    enabled: False
  guardduty:
    enabled: False
  lb:
    enabled: False
    buckets: ['alb-logs-solidarity-tes']
  waf:
    enabled: False
    buckets: ['aws-waf-logs-solidarity-ops']
  vpc_flow_logs:
    enabled: False
    buckets: ['solidarity-ops-vpn-flow-logs']
  cloudtrail:
    enabled: False
    buckets: ['aws-cloudtrail-logs-065229260063-c8d871e5']
  custom:
    enabled: False
    buckets: ['']
  cloudwatch_logs:
    enabled: False
    log_group_names: ['/aws/eks/eks-test/cluster']

github_configs:
  enabled: False
  access_token: ''
  org_name: ['']
  ent_name: ['']
```
---
## How to Use: Execution Examples:

### Setting up defaults
In the utils/constant.py file you can specify:
- Default AWS Profile
- Default AWS Region
- Default output folder
- Default output file name

```python
# CLI TEXT
## DREDGE
dredge_description = "Dredge Threat Hunting"
default_profile = 'default'
default_region = 'us-east-1'
default_output_folder = 'logs_dump_dredge'
default_file_name = "cloud_data_dump"
```

### :thought_balloon: Cloud Status 
1. List S3 buckets
```bash
# Getting S3 buckets
python3 dredge.py cs aws --profile <demo-env> --region <us-east-1> --buckets
```
[![asciicast](https://asciinema.org/a/ONoOypg9l6DipIreyPqD1RK8i.svg)](https://asciinema.org/a/ONoOypg9l6DipIreyPqD1RK8i)


2. Get EC2 Intances
```bash
# Getting EC2 Instances
python3 dredge.py cs aws --profile <demo-env> --region <sa-east-1> --ec2-instances
```
[![asciicast](https://asciinema.org/a/ODyjsOT1zSBkxW9pBYbZSoxh6.svg)](https://asciinema.org/a/ODyjsOT1zSBkxW9pBYbZSoxh6)

3. Security Groups
```bash
# Getting EC2 Instance Security Groups
python3 dredge.py cs aws --profile <demo-env> --region <sa-east-1> --security-groups i-0aaff3273d1a5af1d
```
[![asciicast](https://asciinema.org/a/t8DZ0jtsuZgzp74Sy7hqxp7Uv.svg)](https://asciinema.org/a/t8DZ0jtsuZgzp74Sy7hqxp7Uv)


### :mag: Log Collection 
1. Get Event History Logs
```bash
# Getting Event History Logs
python3 dredge.py lr aws --profile <demo-env> --region <sa-east-1> --log event_history
```
- Filtering API Calls from user_name
- Filtering API Calls from ACCESS_KEY_ID
- Filtering API Calls from Source IP Address

[![asciicast](https://asciinema.org/a/kDoqqL64H2KY72X6m455cixEB.svg)](https://asciinema.org/a/kDoqqL64H2KY72X6m455cixEB)

2. Get Guradduty Events
```bash
# Getting Guardduty Logs
python3 dredge.py lr aws --profile <demo-env> --region <sa-east-1> --log guardduty
```
[![asciicast](https://asciinema.org/a/6ZRXuJInKtoJyMwFGAYU2KVbb.svg)](https://asciinema.org/a/6ZRXuJInKtoJyMwFGAYU2KVbb)

3. Get Logs from S3 Bucket
```bash
# Getting Logs from S3 bucket
python3 dredge.py lr aws --profile <demo-env> --region <sa-east-1> --log s3 --target <solidarity-demo-alb-access-logs>
```
[![asciicast](https://asciinema.org/a/dDLISKS04dctz8MGbWeLNGIcy.svg)](https://asciinema.org/a/dDLISKS04dctz8MGbWeLNGIcy)

### :dart: Threat Hunting
1. Get IPs from file
```bash
# Getting IPs from file
python3 dredge.py th ip --file <guardduty_dredge_dump.json>
```
[![asciicast](https://asciinema.org/a/F8rhPSwfy0ICZDnM4KWUAhnul.svg)](https://asciinema.org/a/F8rhPSwfy0ICZDnM4KWUAhnul)

2. VT Integration
```bash
# Getting and analyzing IPs from file
python3 dredge.py th vt --key <$vt_key> --file <guardduty_dredge_dump.json>
```
[![asciicast](https://asciinema.org/a/pVOtA6HPU94Jfy3qxOtM1lyM3.svg)](https://asciinema.org/a/pVOtA6HPU94Jfy3qxOtM1lyM3)


### :boom: Incident Response
1. Disable Iam User Access Key
```bash
# Disabling an IAM User Access Key
 python3 dredge.py ir aws --profile <ops> --region <us-east-1> disable --access-key <AKIAQ6L7XQUP35ZXPD4E> --iam-user <dredge-log-retriever-user>
```
[![asciicast](https://asciinema.org/a/fdpDLPDoiZNxVIp4uqbdngQ3G.svg)](https://asciinema.org/a/fdpDLPDoiZNxVIp4uqbdngQ3G)


2. Disable S3 public access
```bash
# Disabling S3 Public Access
 python3 dredge.py ir aws --profile <demo-env> --region <us-east-1> disable --s3-public-access <solidarity-demo-alb-access-logs>
```
[![asciicast](https://asciinema.org/a/62BhCq2VyeMKnAGgRdnF8Sl3O.svg)](https://asciinema.org/a/62BhCq2VyeMKnAGgRdnF8Sl3O)


3. Network Isolate an EC2 Instance
```bash
# Isolating an EC2 Instance
 python3 dredge.py ir aws --profile <ops> --region <us-east-1> respond --isolate-ec2-instance <i-0a711ffe3182a2474>
```
[![asciicast](https://asciinema.org/a/y4Gsfxg0bVvh8zrdF748x4jcl.svg)](https://asciinema.org/a/y4Gsfxg0bVvh8zrdF748x4jcl)




