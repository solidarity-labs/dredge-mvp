from modules.class_aws_iam_policy import IAMPolicy

class IAMRole:
    def __init__(self, session, role_name):

        iam_client = session.client('iam')
        response = iam_client.get_role(RoleName=role_name)
        self.role_name = response['Role']['RoleName']
        self.arn = response['Role']['Arn']
        self.create_date = response['Role']['CreateDate']
        self.assume_role_policy_document = response['Role']['AssumeRolePolicyDocument']
        self.policies = self._get_role_policies(session, role_name) or []

    @staticmethod
    def _get_role_policies(session, role_name):
        iam_client = session.client('iam')
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        policies = [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        role_policies = []
        for policy in policies:
            role_policies.append(IAMPolicy.constructor(session, policy))
        return role_policies

    def delete_IAM_role(self, session):
        iam = session.client('iam')

        # Detach all policies from the role
        response = iam.list_attached_role_policies(RoleName=self.role_name)
        for policy in response['AttachedPolicies']:
            iam.detach_role_policy(RoleName=self.role_name, PolicyArn=policy['PolicyArn'])
            print(f"- Detached policy: {policy['PolicyArn']} from role: {self.role_name}")

        # Delete all inline policies from the role
        response = iam.list_role_policies(RoleName=self.role_name)
        for policy_name in response['PolicyNames']:
            iam.delete_role_policy(RoleName=self.role_name, PolicyName=policy_name)
            print(f"- Detached inline policy: {policy_name} from role: {self.role_name}")

        # Remove InstanceProfile
        response = iam.list_instance_profiles_for_role(RoleName=self.role_name)
        instance_profiles = response['InstanceProfiles']

        for instance_profile in instance_profiles:
            iam.remove_role_from_instance_profile(
                RoleName=self.role_name,
                InstanceProfileName=instance_profile['InstanceProfileName']
            )
            print(f"- Removed instance profile: {instance_profile['InstanceProfileName']} from role: {self.role_name}")
            break

        # Delete the IAM role
        iam.delete_role(RoleName=self.role_name)
        print(f"* IAM role {self.role_name} deleted.")

    def detach_polcies_from_role(self, session):
        iam = session.client('iam')

        # Detach all policies from the role
        response = iam.list_attached_role_policies(RoleName=self.role_name)
        for policy in response['AttachedPolicies']:
            iam.detach_role_policy(RoleName=self.role_name, PolicyArn=policy['PolicyArn'])
            print(f"- Detached policy: {policy['PolicyArn']} from role: {self.role_name}")

        # Delete all inline policies from the role
        response = iam.list_role_policies(RoleName=self.role_name)
        for policy_name in response['PolicyNames']:
            iam.delete_role_policy(RoleName=self.role_name, PolicyName=policy_name)
            print(f"- Detached inline policy: {policy_name} from role: {self.role_name}")

        # Remove InstanceProfile
        response = iam.list_instance_profiles_for_role(RoleName=self.role_name)
        instance_profiles = response['InstanceProfiles']

        for instance_profile in instance_profiles:
            iam.remove_role_from_instance_profile(
                RoleName=self.role_name,
                InstanceProfileName=instance_profile['InstanceProfileName']
            )
            print(f"- Removed instance profile: {instance_profile['InstanceProfileName']} from role: {self.role_name}")
            break

