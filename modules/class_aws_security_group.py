import boto3


class SecurityGroup:
    def __init__(self, group_id, group_name, vpc_id, description, tags, rules, region):
        self.group_id = group_id
        self.group_name = group_name
        self.vpc_id = vpc_id
        self.description = description
        self.tags = tags
        self.rules = rules
        self.region = region

    @classmethod
    def constructor(cls, session, group_id, region='us-east-1'):
        ec2_client = session.client('ec2', region)
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = response['SecurityGroups'][0]

        group_id = security_group['GroupId']
        group_name = security_group['GroupName']
        vpc_id = security_group['VpcId']
        description = security_group['Description']
        tags = security_group.get('Tags', [])
        rules = security_group['IpPermissions']

        return cls(group_id, group_name, vpc_id, description, tags, rules, region)

