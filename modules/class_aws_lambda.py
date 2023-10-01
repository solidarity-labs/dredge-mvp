import boto3
import time
import json

class LambdaFunction:
    def __init__(self, session, function_name, region='us-east-1'):
        lambda_client = session.client('lambda', region)
        response = lambda_client.get_function_configuration(FunctionName=function_name)

        self.region = region
        self.function_name = response['FunctionName']
        self.runtime = response['Runtime']
        self.handler = response['Handler']
        self.memory_size = response['MemorySize']
        self.timeout = response['Timeout']
        self.role_arn = response['Role']
        self.environment_variables = response.get('Environment', {}).get('Variables', {})


    #TESTING REQUIRED
    @staticmethod
    def remove_lambda_roles(function_name, session):
        lambda_client = session.client('lambda')
        role_name, role_arn = create_lambda_forensic_role(session)
        time.sleep(5)

        response = lambda_client.update_function_configuration(
            FunctionName=function_name,
            Role=f'{role_arn}'
        )

        print(f"* IAM Role removed from Lambda function '{function_name}'")

    @staticmethod
    def delete_lambda(function_name, session):
        lambda_client = session.client('lambda')

        try:
            response = lambda_client.delete_function(FunctionName=function_name)
            print(f"Lambda function '{function_name}' deleted successfully.")
        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"Lambda function '{function_name}' not found.")
        except Exception as e:
            print(f"Error deleting lambda function: {e}")


def create_lambda_forensic_role(session):
    iam_client = session.client('iam')
    role_name = 'forensics_dredge_lambda_role'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='IAM role for Lambda function with no permissions'
        )
        role_arn = response['Role']['Arn']
        print(f"- IAM role '{role_name}' created for Lambda function")
    except Exception as e:
        print(f'- {role_name} already exists, so we are going to try to find the ARN')
        role_arn = get_iam_role_arn(role_name, session)
        if role_arn:
            print(f'- We found it! Role ARN: {role_arn}')
            print(f'!! Please, review that the role {role_name} has no permissions so it can be effective')

    return role_name, role_arn


def get_iam_role_arn(role_name, session):
    iam_client = session.client('iam')

    response = iam_client.list_roles()

    for role in response['Roles']:
        if role['RoleName'] == role_name:
            return role['Arn']

    return None
