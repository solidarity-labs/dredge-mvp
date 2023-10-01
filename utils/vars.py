th_csv_file_name = 'dredge_th_report.csv'
th_json_file_name = 'dredge_th_report.json'
flag = "tabulated"

dangerous_k8s_criteria = [
    # Pods: Allows creating, deleting, or patching pods, which can disrupt workloads.
    {"api_groups": [""], "resources": ["pods"], "verbs": ["create", "delete", "patch"]},
    
    # Nodes: Allows creating, deleting, or patching nodes, which can impact the cluster infrastructure.
    {"api_groups": [""], "resources": ["nodes"], "verbs": ["create", "delete", "patch"]},
    
    # ConfigMaps: Allows deleting or patching ConfigMaps, affecting application configurations.
    {"api_groups": [""], "resources": ["configmaps"], "verbs": ["delete", "patch"]},
    
    # Deployments: Allows deleting or patching Deployments, impacting application deployments.
    {"api_groups": [""], "resources": ["deployments"], "verbs": ["delete", "patch"]},
    
    # All Resources: Allows all verbs (create, delete, patch) on all resources, which is highly permissive.
    {"api_groups": [""], "resources": ["*"], "verbs": ["*"]},

    # Additional examples:
    
    # Deployments (apps API group): Allows control over application deployments, impacting availability.
    {"api_groups": ["apps"], "resources": ["deployments"], "verbs": ["create", "delete", "patch"]},
    
    # Deployments (extensions API group): Similar to "apps" deployments, impacting application deployments.
    {"api_groups": ["extensions"], "resources": ["deployments"], "verbs": ["create", "delete", "patch"]},
    
    # Secrets: Allows creating, deleting, or patching secrets, which can lead to data exposure.
    {"api_groups": [""], "resources": ["secrets"], "verbs": ["create", "delete", "patch"]},
    
    # PersistentVolumeClaims: Allows creating, deleting, or patching PVCs, affecting storage.
    {"api_groups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["create", "delete", "patch"]},
]

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

dangerous_api_call_dict = dangerous_api_calls = {
    # Amazon S3
    'LookupEvents': 'testing',
    'CreateBucket': 'Can create new S3 buckets, which might lead to data exposure or unintended costs.',
    'DeleteBucket': 'Can delete S3 buckets, potentially leading to data loss.',
    'PutBucketPolicy': 'Can modify bucket policies, affecting access controls for objects.',
    'DeleteBucketPolicy': 'Can remove bucket policies, potentially impacting access controls.',
    'PutObject': 'Allows uploading objects to S3 buckets, possibly exposing sensitive data.',
    'DeleteObject': 'Allows deleting objects from S3 buckets, potentially leading to data loss.',

    # Amazon EC2
    
    'TerminateInstances': 'Can terminate EC2 instances, affecting availability.',
    'StopInstances': 'Can stop EC2 instances, impacting availability and services.',
    'StartInstances': 'Can start EC2 instances, affecting availability and services.',
    'RebootInstances': 'Can reboot EC2 instances, impacting availability and services.',
    'CreateImage': 'Allows creating Amazon Machine Images (AMIs), affecting instance configurations.',
    'DeleteSnapshot': 'Can delete EBS snapshots, potentially impacting data backups.',

    # AWS IAM
    
    'CreateUser': 'Can create IAM users, which can lead to unauthorized access.',
    'DeleteUser': 'Can delete IAM users, potentially disrupting user access.',
    'CreateAccessKey': 'Can create IAM access keys, potentially compromising security.',
    'DeleteAccessKey': 'Can delete IAM access keys, potentially disrupting user access.',
    'CreateLoginProfile': 'Can create IAM user login profiles, affecting user authentication.',
    'DeleteLoginProfile': 'Can delete IAM user login profiles, impacting user authentication.',
    'CreateGroup': 'Can create IAM groups, potentially impacting user and policy management.',
    'DeleteGroup': 'Can delete IAM groups, potentially disrupting user and policy management.',
    'CreatePolicy': 'Allows creating IAM policies, potentially affecting security policies.',
    'DeletePolicy': 'Allows deleting IAM policies, potentially impacting security policies.',
    'AttachUserPolicy': 'Can attach policies to IAM users, potentially granting excessive permissions.',
    'AttachGroupPolicy': 'Can attach policies to IAM groups, potentially granting excessive permissions.',
    'AttachRolePolicy': 'Can attach policies to IAM roles, potentially granting excessive permissions.',
    'DetachUserPolicy': 'Can detach policies from IAM users, potentially revoking necessary permissions.',
    'DetachGroupPolicy': 'Can detach policies from IAM groups, potentially revoking necessary permissions.',
    'DetachRolePolicy': 'Can detach policies from IAM roles, potentially revoking necessary permissions.',

    # Amazon RDS
    
    'DeleteDBInstance': 'Can delete RDS database instances, potentially leading to data loss.',
    'DeleteDBSnapshot': 'Can delete RDS database snapshots, potentially impacting data backups.',
    'DeleteDBCluster': 'Can delete RDS database clusters, potentially leading to data loss.',
    'DeleteDBClusterSnapshot': 'Can delete RDS database cluster snapshots, impacting data backups.',

    # AWS Lambda
    
    'DeleteFunction': 'Can delete Lambda functions, potentially affecting application functionality.',
    'DeleteLayerVersion': 'Can delete Lambda layer versions, potentially impacting Lambda functions.',
    'UpdateFunctionCode': 'Allows updating Lambda function code, affecting application behavior.',
    'UpdateFunctionConfiguration': 'Allows updating Lambda function configurations, impacting behavior.',

    # Amazon DynamoDB
    
    'DeleteTable': 'Can delete DynamoDB tables, potentially leading to data loss.',
    'DeleteItem': 'Can delete items from DynamoDB tables, potentially impacting data integrity.',
    'UpdateItem': 'Allows updating items in DynamoDB tables, affecting data integrity.',
    'PutItem': 'Allows adding items to DynamoDB tables, affecting data integrity.',

    # AWS CloudFormation
    
    'DeleteStack': 'Can delete CloudFormation stacks, potentially impacting infrastructure.',
    'CreateStack': 'Allows creating CloudFormation stacks, affecting infrastructure.',
    'UpdateStack': 'Can update CloudFormation stacks, potentially impacting infrastructure.',
    'CreateChangeSet': 'Allows creating CloudFormation change sets, affecting stack updates.',
    'DeleteChangeSet': 'Can delete CloudFormation change sets, impacting stack updates.',

    # Amazon SQS
    
    'DeleteQueue': 'Can delete SQS queues, potentially disrupting message processing.',
    'SendMessage': 'Allows sending messages to SQS queues, impacting message flow.',
    'DeleteMessage': 'Can delete messages from SQS queues, affecting message processing.',

    # Amazon SNS
    
    'DeleteTopic': 'Can delete SNS topics, potentially disrupting notifications.',
    'Publish': 'Allows publishing messages to SNS topics, impacting notification delivery.',
    'Subscribe': 'Can subscribe to SNS topics, potentially accessing sensitive information.',

    # AWS Secrets Manager
    
    'DeleteSecret': 'Can delete secrets in Secrets Manager, potentially leading to data loss.',
    'PutSecretValue': 'Allows putting secret values in Secrets Manager, affecting data security.',
    'RestoreSecret': 'Can restore deleted secrets in Secrets Manager, affecting data retention.',

    # Amazon EC2 Auto Scaling
    
    'DeleteAutoScalingGroup': 'Can delete EC2 Auto Scaling groups, affecting scaling policies.',
    'UpdateAutoScalingGroup': 'Allows updating EC2 Auto Scaling groups, impacting scaling.',

    # AWS Elastic Beanstalk
    
    'DeleteApplication': 'Can delete Elastic Beanstalk applications, affecting application deployments.',
    'DeleteEnvironment': 'Allows deleting Elastic Beanstalk environments, impacting services.',

    # AWS Identity and Access Management
    
    'DeleteVirtualMFADevice': 'Can delete virtual MFA devices, impacting user authentication.',
    'DeactivateMFADevice': 'Allows deactivating MFA devices, affecting user security.'
}

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