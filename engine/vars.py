th_csv_file_name = 'dredge_th_report.csv'
th_json_file_name = 'dredge_th_report.json'

valid_aws_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "ca-central-1",
        "eu-north-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
        "eu-south-1",
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2",
        "ap-south-1",
        "sa-east-1",
        "cn-north-1", "cn-northwest-1",
        "af-south-1",
        "me-south-1"
    ]
dangerous_api_calls = [
    # Amazon S3
    'CreateBucket',
    'DeleteBucket',
    'PutBucketPolicy',
    'DeleteBucketPolicy',
    'PutObject',
    'DeleteObject',

    # Amazon EC2
    'TerminateInstances',
    'StopInstances',
    'StartInstances',
    'RebootInstances',
    'CreateImage',
    'DeleteSnapshot',

    # AWS IAM
    'CreateUser',
    'DeleteUser',
    'CreateAccessKey',
    'DeleteAccessKey',
    'CreateLoginProfile',
    'DeleteLoginProfile',
    'CreateGroup',
    'DeleteGroup',
    'CreatePolicy',
    'DeletePolicy',
    'AttachUserPolicy',
    'AttachGroupPolicy',
    'AttachRolePolicy',
    'DetachUserPolicy',
    'DetachGroupPolicy',
    'DetachRolePolicy',

    # Amazon RDS
    'DeleteDBInstance',
    'DeleteDBSnapshot',
    'DeleteDBCluster',
    'DeleteDBClusterSnapshot',

    # AWS Lambda
    'DeleteFunction',
    'DeleteLayerVersion',
    'UpdateFunctionCode',
    'UpdateFunctionConfiguration',

    # Amazon DynamoDB
    'DeleteTable',
    'DeleteItem',
    'UpdateItem',
    'PutItem',

    # AWS CloudFormation
    'DeleteStack',
    'CreateStack',
    'UpdateStack',
    'CreateChangeSet',
    'DeleteChangeSet',

    # Amazon SQS
    'DeleteQueue',
    'SendMessage',
    'DeleteMessage',

    # Amazon SNS
    'DeleteTopic',
    'Publish',
    'Subscribe',

    # AWS Secrets Manager
    'DeleteSecret',
    'PutSecretValue',
    'RestoreSecret',

    # Amazon EC2 Auto Scaling
    'DeleteAutoScalingGroup',
    'UpdateAutoScalingGroup',

    # AWS Elastic Beanstalk
    'DeleteApplication',
    'DeleteEnvironment',

    # AWS Identity and Access Management
    'DeleteVirtualMFADevice',
    'DeactivateMFADevice'
]