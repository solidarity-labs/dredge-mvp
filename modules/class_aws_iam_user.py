from modules.class_aws_iam_policy import IAMPolicy, IAMInlinePolicy
import botocore

class IAMUser:
    def __init__(self, session, username):
        iam_client = session.client('iam')

        response = iam_client.get_user(UserName=username)
        self.user_name = username
        self.arn = response['User']['Arn']
        self.create_date = response['User']['CreateDate']
        self.access_keys = self._get_access_keys(iam_client, username) or []
        #self.groups = self._get_user_groups(iam_client, username) or []
        #self.policies = self._get_user_policies(session, username) or []
        #self.inline_policies = self._get_inline_policies(session, username) or []
        self.mfa = self._get_user_mfa(iam_client)
        self.login_profile = self._get_user_loging_profile(iam_client)
        #self.acces_advisor = self._get_user_access_advisor(iam_client)


    def _get_user_mfa(self, iam_client):
        response = iam_client.list_mfa_devices(UserName=self.user_name)
        mfa_devices = response.get('MFADevices', [])
        if mfa_devices:
            return True
        else:
            return False

    def _get_user_access_advisor(self, iam_client):
        response = iam_client.generate_service_last_accessed_details(
            Arn=self.arn,
            Granularity='SERVICE_LEVEL'
        )
        job_id = response.get('JobId')
        while True:

            response = iam_client.get_service_last_accessed_details(
                JobId=job_id)

            if response['JobStatus'] == 'IN_PROGRESS':
                continue

            else:
                return(response)

    def _get_user_loging_profile(self, iam_client):
        try:
            response = iam_client.get_login_profile(UserName=self.user_name)
            if 'LoginProfile' in response:
                return True
            return False
        except Exception as e:
            return False

    @staticmethod
    def _get_access_keys(iam_client, username):
        response = iam_client.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']
        return access_keys

    @staticmethod
    def _get_user_groups(iam_client, username):

        response = iam_client.list_groups_for_user(UserName=username)
        groups = [group['GroupName'] for group in response['Groups']]
        return groups

    @staticmethod
    def _get_user_policies(session, username):
        iam_client = session.client('iam')
        response = iam_client.list_attached_user_policies(UserName=username)
        policies = [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        iam_policies = []
        for policy in policies:
            iam_policy = IAMPolicy.constructor(session, policy)
            iam_policies.append(iam_policy)
        return iam_policies

    @staticmethod
    def _get_inline_policies(session, username):
        iam_client = session.client('iam')
        response = iam_client.list_user_policies(UserName=username)
        policies = response['PolicyNames']
        inline_policies = []
        for policy in policies:
            inline_policy = IAMInlinePolicy.constructor(session, username, policy)
            inline_policies.append(inline_policy)

        return inline_policies

    #INIDENT RESPONSE
    @staticmethod
    def disable_access_key(access_key_id, iam_user_name, session):
        iam = session.client('iam')

        # Disable the access key
        try:
            response = iam.update_access_key(
                AccessKeyId=access_key_id,
                Status='Inactive',
                UserName=iam_user_name
            )
            print(f"* Access key {access_key_id} for IAM user {iam_user_name} disabled.")
            return response
        except Exception as e:
            print(e)    

    @staticmethod
    def delete_IAM_user(iam_user_name, session):
        iam = session.client('iam')

        response = iam.list_access_keys(UserName=iam_user_name)
        access_keys = response['AccessKeyMetadata']

        for key in access_keys:
            access_key_id = key['AccessKeyId']
            iam.delete_access_key(UserName=iam_user_name, AccessKeyId=access_key_id)
            print(f"- Deleted access key: {access_key_id} for user: {iam_user_name}")

        # List the attached policies for the user
        attached_policies = iam.list_attached_user_policies(UserName=iam_user_name)
        # Detach each attached policy
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            iam.detach_user_policy(UserName=iam_user_name, PolicyArn=policy_arn)
            print(f"- Detached policy: {policy_arn} from user: {iam_user_name}")

        
        # Delete Login Profile
        try:
            iam.delete_login_profile(UserName=iam_user_name)
            print("* Console access removed for user:", iam_user_name)
        except iam.exceptions.NoSuchEntityException:
            print("- User does not have a login profile. Console access removal is not required.")
        except Exception as e:
            print("Error removing console access for user:", iam_user_name)
            print("Error message:", str(e))


        # Delete the IAM user
        try:
            response = iam.delete_user(UserName=iam_user_name)
            print(f"* IAM user {iam_user_name} deleted.")
            return response
        except Exception as e:
            print(e)

    def remove_login_profile(self, session):
        iam_client = session.client('iam')
        try:
            iam_client.delete_login_profile(UserName=self.user_name)
            print("* Console access removed for user:", self.user_name)
            
        except iam_client.exceptions.NoSuchEntityException:
            print("- User does not have a login profile. Console access removal is not required.")
        except Exception as e:
            print("Error removing console access for user:", self.user_name)
            print("Error message:", str(e))


    def disable_all_access_key(self, session):
        iam = session.client('iam')
        for key in self.access_keys:
            try:
                response = iam.update_access_key(
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive',
                    UserName=self.user_name
                )
                print(f"* Access key {key['AccessKeyId']} for IAM user {self.user_name} disabled.")

            except Exception as e:
                print(e)
