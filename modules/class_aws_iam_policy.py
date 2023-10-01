import boto3

class IAMPolicy:
    def __init__(self, policy_name, arn, create_date, policy_document):
        self.policy_name = policy_name
        self.arn = arn
        self.create_date = create_date
        self.policy_document = policy_document

    @classmethod
    def constructor(cls, session, policy_arn):
        iam_client = session.client('iam')

        response = iam_client.get_policy(PolicyArn=policy_arn)

        policy_name = response['Policy']['PolicyName']
        arn = response['Policy']['Arn']
        create_date = response['Policy']['CreateDate']

        policy_version = response['Policy']['DefaultVersionId']
        policy_document = cls._get_policy_document(iam_client, arn, policy_version)

        return cls(policy_name, arn, create_date, policy_document)

    @staticmethod
    def _get_policy_document(iam_client, policy_arn, policy_version):
        response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
        policy_document = response['PolicyVersion']['Document']
        return policy_document


class IAMInlinePolicy:
    def __init__(self, policy_name, policy_document):
        self.policy_name = policy_name
        self.policy_document = policy_document

    @classmethod
    def constructor(cls, session, user_name, policy_name):
        iam_client = session.client('iam')

        response = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)

        policy_name = response['PolicyName']
        policy_document = response['PolicyDocument']

        return cls(policy_name, policy_document)


#TESTING REQUIRED
# ADD ATTRIBUTE TO CONSTRUCTOR
def has_iam_interaction_policy(policy_version):
    dangerous_actions = [
        # ROOT
        "*",

        # IAM Actions
        "iam:*",
        "iam:AddUserToGroup",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:CreateRole",
        "iam:CreateUser",
        "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:DeleteRole",
        "iam:DeleteUser",
        "iam:DetachGroupPolicy",
        "iam:DetachRolePolicy",
        "iam:DetachUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:RemoveUserFromGroup",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAccessKey",
        "iam:UpdateLoginProfile",
        "iam:UpdatePolicy",
        "iam:UpdateRole",
        "iam:UpdateUser",

        # EC2 Actions
        "ec2:*",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:ModifyInstanceAttribute",
        "ec2:RunInstances",
        "ec2:TerminateInstances",

        # S3 Actions
        "s3:*",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",

        # RDS Actions
        "rds:*",
        "rds:CreateDBInstance",
        "rds:DeleteDBInstance",
        "rds:ModifyDBInstance",

        # Lambda Actions
        "lambda:*",
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",

        # CloudFormation Actions
        "cloudformation:*",
        "cloudformation:CreateStack",
        "cloudformation:DeleteStack",
        "cloudformation:UpdateStack"
    ]

    dangerous_api_calls = []
    # Check if the policy version allows IAM interaction
    statements = policy_version.get('Statement', [])
    for statement in statements:
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
            for action in actions:
                if action in dangerous_actions:
                    dangerous_api_calls.append(action)
                    if dangerous_api_calls:
                        print(f'DANGER - Policy with dangerous API Calls {dangerous_api_calls}')

    return dangerous_api_calls