from modules.class_aws_iam_policy import IAMPolicy


class IAMGroup:
    def __init__(self, session, group_name):

        iam_client = session.client('iam')
        response = iam_client.get_group(GroupName=group_name)

        self.group_name = response['Group']['GroupName']
        self.arn = response['Group']['Arn']
        self.create_date = response['Group']['CreateDate']
        self.users = self._get_group_users(iam_client, group_name) or []
        self.policies = self._get_group_policies(session, group_name) or []


    @staticmethod
    def _get_group_users(iam_client, group_name):
        response = iam_client.get_group(GroupName=group_name)
        users = response['Users']
        return users

    @staticmethod
    def _get_group_policies(session, group_name):
        iam_client = session.client('iam')
        response = iam_client.list_attached_group_policies(GroupName=group_name)
        policies = [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        group_policies = []
        for policy in policies:
            group_policies.append(IAMPolicy.constructor(session, policy))
        return group_policies

    def delete_IAM_group(self, session):
        iam = session.client('iam')
        # Remove IAM Users
        response = iam.get_group(GroupName=self.group_name)
        users = response['Users']

        for user in users:
            username = user['UserName']
            iam.remove_user_from_group(GroupName=self.group_name, UserName=username)
            print(f"- Removed user '{username}' from group: {self.group_name}")

        # Remove IAM Policies
        response = iam.list_attached_group_policies(GroupName=self.group_name)
        policies = response['AttachedPolicies']

        for policy in policies:
            policy_arn = policy['PolicyArn']
            iam.detach_group_policy(GroupName=self.group_name, PolicyArn=policy_arn)
            print(f"- Detached policy  '{policy_arn}' from group: {self.group_name}")

        # Delete the IAM group
        try:
            response = iam.delete_group(GroupName=self.group_name)
            print(f"* IAM group '{self.group_name}' deleted.")
            return response
        except Exception as e:
            print(e)

    def detach_policies_from_group(self, session):
        iam = session.client('iam')
        # Remove IAM Users
        response = iam.get_group(GroupName=self.group_name)
        users = response['Users']

        for user in users:
            username = user['UserName']
            iam.remove_user_from_group(GroupName=self.group_name, UserName=username)
            print(f"- Removed user: {username} from group: {self.group_name}")

        # Remove IAM Policies
        response = iam.list_attached_group_policies(GroupName=self.group_name)
        policies = response['AttachedPolicies']

        for policy in policies:
            policy_arn = policy['PolicyArn']
            iam.detach_group_policy(GroupName=self.group_name, PolicyArn=policy_arn)
            print(f"- Detached policy: {policy_arn} from group: {self.group_name}")
