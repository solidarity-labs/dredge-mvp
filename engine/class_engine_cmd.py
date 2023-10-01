import cmd
import pyfiglet
import botocore.exceptions
import os
import whois
import re
from pprint import pprint
from tqdm import tqdm
from tabulate import tabulate
from engine.class_engine_threat_hunting import ThreatHunting, shodan_enrichment, vt_analyze_file, vt_analyze_ip, vt_analyze_domain, vt_analyze_hash, get_event_history_alerts
from engine.class_engine_log_retriever import LogRetriever, log_retriever_from_file
from engine.class_engine_auth import AWSAuth
from modules.class_github import Github
from modules.class_aws_iam_user import IAMUser
from modules.class_aws_iam_group import IAMGroup
from modules.class_aws_iam_role import IAMRole
from modules.class_aws_lambda import LambdaFunction
from modules.class_aws_s3_bucket import S3Bucket
from modules.class_aws_rds_instance import RDSInstance
from modules.class_aws_security_group import SecurityGroup
from modules.class_aws_eks import EKSCluster
from modules.class_aws_ec2_instance import EC2Instance


class DredgeCLI(cmd.Cmd):
    print(pyfiglet.figlet_format("Dredge"))
    intro = "Welcome to Dredge! Type 'help' for a list of commands. \n" \
            "\n" \
            "- C: Config: The tool will use a config file, better to retrieve multiple logs. \n" \
            "- CS: Get security deviations from the cloud provider using Prowler open source tool. \n" \
            "- LR: Log Retriever: Tool to get logs in an easy manner from multiple cloud sources. \n" \
            "- IR: Incident Response: Tool to remediate deviations. \n" \
            "- TH: Threat Hunting: Tool to execute a quick and dirty threat hunting exercise in your environment. \n"
    prompt = "Dredge: "

    def do_C(self, arg):
        '''The tool will use a config file, better to retrieve multiple logs.'''
        print()
        config_file = input('Config file (config.yaml): ')
        log_retriever_from_file(config_file)

    def do_CS(self, arg):
        '''Get security deviations from the cloud provider using Prowler open source tool.'''
        print()
        cloud_status = CMDCloudStatus()
        cloud_status.cmdloop()

    def do_LR(self, arg):
        """Tool to get logs in an easy manner from multiple cloud sources."""
        print()
        start_date = input('Start Date <2023-03-01>: ')
        end_date = input('End Date <2023-04-01>: ')
        destination_folder = input('Destination Folder Name: ')
        output_file = input('Output File Name: ')

        try:
            os.mkdir(destination_folder)
        except FileExistsError as e:
            pass

        log_retriever = LogRetriever(start_date, end_date, destination_folder, output_file)

        try:
            log_retriever = CMDLogRetriever(log_retriever)
            log_retriever.cmdloop()
        except KeyboardInterrupt as e:
            print()
            return True

    def do_IR(self, arg):
        """Tool to remediate deviations."""
        try:
            incident_response = CMDIncidentResponse()
            incident_response.cmdloop()
        except KeyboardInterrupt as e:
            print()

    def do_TH(self, arg):
        """Tool to execute a quick and dirty threat hunting exercise in your environment."""
        try:
            threat_hunting = CMDThreatHunting()
            threat_hunting.cmdloop()
        except KeyboardInterrupt as e:
            print()
            pass

    def do_exit(self, arg):
        """Exit the CLI"""
        return True


class CMDCloudStatus(cmd.Cmd):
    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- AWS: Get AWS Logs [LB / WAF / Cloudtrail / Event History / Guardduty / Cloudwatch Logs / Custom S3 Objects] \n" \
            "- Github: Get Github Logs (Enterprise Subscription Needed) \n" \
            "- Kubernetes: TBD \n" \
            "- Azure: TBD \n"
    prompt = "Dredge - Cloud Status: "

    def do_AWS(self, arg):
        """Azure Log Retriever CLI"""
        pass

    def do_GCP(self, arg):
        """Azure Log Retriever CLI"""
        return True

    def do_Azure(self, arg):
        """Azure Log Retriever CLI"""
        return True

    def do_K8s(self, arg):
        """Kubernetes Log Retriever CLI"""
        return True


class CMDLogRetriever(cmd.Cmd):
    def __init__(self, log_retriever):
        super().__init__()
        self.log_retriever = log_retriever

    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- AWS: Get AWS Logs [LB / WAF / Cloudtrail / Event History / Guardduty / Cloudwatch Logs / Custom S3 Objects] \n" \
            "- Github: Get Github Logs (Enterprise Subscription Needed) \n" \
            "- Kubernetes: TBD \n" \
            "- Azure: TBD \n"
    prompt = "Dredge - Log Retriever: "

    def do_AWS(self, arg):
        """AWS Log Retriever CLI"""

        try:
            profile = input('AWS Profile: ')
            region = input('AWS Region: ')
            session = AWSAuth(profile, region).session
            AWS_log_retriever = AWSLogRetriever(session, self.log_retriever)
            AWS_log_retriever.cmdloop()

        except Exception as e:
            print(e)

        except KeyboardInterrupt as e:
            print()
            return True

    def do_Github(self, arg):
        """Github Log Retriever CLI"""
        org_name = input('Github Organization Name: ')
        access_token = input('Github Access Token: ')
        print('[Github Logs]')
        print(f'- Starting to retrieve logs from "{org_name}" Github Organization')
        try:
            github = Github(access_token, org_name)
            self.log_retriever.get_github_logs(github)
        except Exception as e:
            print(e)

    def do_Azure(self, arg):
        """Azure Log Retriever CLI"""
        return True

    def do_K8s(self, arg):
        """Kubernetes Log Retriever CLI"""
        return True

    def do_exit(self, arg):
        """Back to Dredge CLI"""
        return True


class AWSLogRetriever(cmd.Cmd):
    def __init__(self, session, log_retriever):
        super().__init__()
        self.session = session
        self.log_retriever = log_retriever


    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- s3: Retrieve logs stored in an S3 bucket (WAF, ALB, Cloudtrail, etc)  \n" \
            "- Guardduty: Retrieve logs from Guardduty API \n" \
            "- EventHistory: Retrieve Cloudtrail Logs from the Event History API \n" \
            "- CloudwatchLogs: Retrieve Logs from Cloudwatch Logs Groups \n"

    prompt = "Dredge - Log Retriever | AWS: "

    def do_s3(self, arg):
        """Retrieve logs stored in an S3 bucket (WAF, ALB, Cloudtrail, etc)"""
        s3_bucket_name = input("S3 Bucket Name: ")
        session = self.session
        print()
        print(f'- Starting to retrieve logs from "{s3_bucket_name}" S3 bucket')
        print()

        try:
            self.log_retriever.get_s3_logs(session, s3_bucket_name)
        except botocore.exceptions.ParamValidationError as e:
            print(e)

        except KeyboardInterrupt as e:
            pass

    def do_Guardduty(self, arg):
        """Retrieve logs from Guardduty API"""
        session = self.session
        print()
        print(f'[Guardduty]')
        print(f'- Starting to retrieve logs from "Guardduty"')

        try:
            self.log_retriever.get_guardduty_findings(session)
            print()
            print(f'- Writing logs into "{self.log_retriever.destination_path}" folder')
            self.log_retriever.json_reporter()

        except botocore.exceptions.ParamValidationError as e:
            print(e)

        except KeyboardInterrupt as e:
            pass

    def do_EventHistory(self, arg):
        """Retrieve Cloudtrail Logs from the Event History API"""
        session = self.session
        print()
        print(f'[Event History]')
        print(f'- Starting to retrieve logs from "Event History"')
        try:
            self.log_retriever.get_event_history_logs(session)
            print()
            print(f'- Writing logs into "{self.log_retriever.destination_path}" folder')
            self.log_retriever.json_reporter()
        except botocore.exceptions.ParamValidationError as e:
            print(e)

        except KeyboardInterrupt as e:
            pass

    def do_CloudwatchLogs(self, arg):
        """Retrieve Logs from Cloudwatch Logs Groups"""
        log_group_name = input("Log Group Name: ")

        print()
        print(f"[Cloudwatch Logs]")
        print(f'- Starting to retrieve logs from "{log_group_name}" Log Group')
        try:
            self.log_retriever.get_cloudwatch_logs(self.session, log_group_name)
            print()
            print(f'- Writing logs into "{self.log_retriever.destination_path}" folder')
            self.log_retriever.json_reporter()
        except botocore.exceptions.ParamValidationError as e:
                print(e)

        except KeyboardInterrupt as e:
            pass


class CMDIncidentResponse(cmd.Cmd):

    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- AWS: Remediate AWS Deviations (IAM Users, EC2 Instances, etc.) \n" \
            "- Github: Get Github Logs (Enterprise Subscription Needed) \n" \
            "- Kubernetes: TBD \n" \
            "- Azure: TBD \n"
    prompt = "Dredge - Incident Response: "

    def do_AWS(self, arg):
        """AWS Log Retriever CLI"""
        try:
            print('- We need some data for AWS Authentication: ')
            profile = input('AWS Profile: ')
            region = input('AWS Region: ')
            session = AWSAuth(profile, region).session
            aws_incident_response = AWSIncidentResponse(session, region)
            aws_incident_response.cmdloop()
        except Exception as e:
            print(e)

        except KeyboardInterrupt as e:
            print()
            return True

    def do_exit(self, arg):
        """Back to Dredge CLI"""
        return True


class AWSIncidentResponse(cmd.Cmd):
    def __init__(self, session, region):
        super().__init__()
        self.session = session
        self.region = region


    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- IAM: Identity and Access Management, users and stuff \n" \
            "- EC2: Elastic Compute Cloud, servers\n" \
            "- Lambda: Serverless compute\n" \
            "- S3: Simple Storage Service, Object Storage... it's not simple :D\n" \
            "- EKS: Elastic Kubernetes Service \n" \
            "- RDS: Relational Database Service, Databases \n"

    prompt = "Dredge - Incident Response | AWS: "

    def do_IAM(self, arg):
        ir_options = ['AWS - List IAM Users', 'AWS - List IAM Users Access Keys', 'AWS - Disable IAM User AccessKey',
                      'AWS - Disable ALL User AccessKey', 'AWS - Delete IAM User',
                      'AWS - Remove Console Login Access from User', 'AWS - Delete IAM Group',
                      'AWS - Detach Policies from Group', 'AWS - Delete IAM Role', 'AWS - Back']
        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)

        if ir_choice == 'AWS - List IAM Users':
            iam_client = self.session.client('iam')
            response = iam_client.list_users()
            headers = ['User Name', 'AccessKeys', 'MFA Status', 'Has Console Access', 'Creation Date']
            data = []
            data.append(headers)
            if 'Users' in response:
                print('* Now we are going to get all IAM Users: ')
                users = response['Users']
                for user in tqdm(users, desc="Processing", unit="item"):
                    access_keys = []
                    user_name = user['UserName']
                    iam_user = IAMUser(self.session, user_name)
                    for i in iam_user.access_keys:
                        access_keys.append(i['AccessKeyId'])
                    formated_dt = iam_user.create_date.strftime("%B %d, %Y %H:%M:%S %p")
                    iam_user_data = [iam_user.user_name, access_keys, iam_user.mfa, iam_user. login_profile, formated_dt]
                    data.append(iam_user_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - List IAM Users Access Keys':
            iam_client = self.session.client('iam')
            response = iam_client.list_users()
            headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
            data = []
            data.append(headers)
            if 'Users' in response:
                print('* Now we are going to get all IAM Users Access Keys: ')
                users = response['Users']
                for user in tqdm(users, desc="Processing", unit="item"):
                    access_keys = []
                    user_name = user['UserName']
                    iam_user = IAMUser(self.session, user_name)
                    for i in iam_user.access_keys:
                        formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
                        access_key_data = [i['AccessKeyId'], i['Status'], user_name, formatted_dt]
                        data.append(access_key_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - Disable IAM User AccessKey':
            access_key_id = input('ACCESS KEY ID: ')
            iam_user_name = input('IAM User Name: ')
            print(f'* - Now we are going to disable the ACCESS KEY ID {access_key_id} from the user {iam_user_name}')
            try:
                user = IAMUser(self.session, iam_user_name)
                user.disable_access_key(access_key_id, iam_user_name, self.session)
            except Exception as e:
                print(e)
            print()


        if ir_choice == 'AWS - Disable ALL User AccessKey':
            iam_user_name = input('IAM User Name: ')
            print(f'* - Now we are going to disable ALL ACCESS KEYS from the user {iam_user_name}')
            try:
                user = IAMUser(self.session, iam_user_name)
                user.disable_all_access_key(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Delete IAM User':
            iam_user_name = input('IAM User Name: ')
            print(f'* - Now we are going to delete the IAM USER {iam_user_name}')
            try:
                user = IAMUser(self.session, iam_user_name)
                user.delete_IAM_user(iam_user_name, self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Remove Console Login Access from User':
            iam_user_name = input('IAM User Name: ')
            print(f'* - Now we are going to remove Login Access from the user {iam_user_name}')
            try:
                user = IAMUser(self.session, iam_user_name)
                user.remove_login_profile(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Delete IAM Group':
            iam_group_name = input('IAM Group Name: ')
            print(f'* - Now we are going to delete the IAM GROUP {iam_group_name}')
            try:
                group = IAMGroup(self.session, iam_group_name)
                group.delete_IAM_group(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Detach Policies from Group':
            iam_group_name = input('IAM Group Name: ')
            print(f'* - Now we are going to detach the IAM Policies from the IAM GROUP {iam_group_name}')
            try:
                group = IAMGroup(self.session, iam_group_name)
                group.detach_policies_from_group(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Delete IAM Role':
            iam_role_name = input('IAM Role Name: ')
            print(f'* - Now we are going to delete the IAM ROLE {iam_user_name}')
            try:
                role = IAMRole(self.session, iam_role_name)
                role.delete_IAM_role(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Detach IAM Role Policies':
            iam_role_name = input('IAM Role Name: ')
            print(f'* - Now we are going to detach de IAM Policies from the IAM ROLE {iam_role_name}')
            try:
                role = IAMRole(self.session, iam_role_name)
                role.detach_polcies_from_role(self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Back':
            pass

    def do_EC2(self, arg):
        ir_options = ['AWS - Get EC2 Instances', 'AWS - Acquire Instance Profile', 'AWS - Remove Instance Profile',
                      'AWS - Acquire EC2 Volume Image (Snapshot)', 'AWS - Enable EC2 termination protection',
                      'AWS - TAG EC2 instance for Forensics', 'AWS - Isolate EC2 Instance',
                      'AWS - Terminate EC2 Instance', 'AWS - Back']

        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)

        if ir_choice == 'AWS - Get EC2 Instances':
            regions = input('AWS Regions (Space Separated, default us-east-1): ')
            if regions == '':
                regions = ['us-east-1']
            elif regions == '*':
                regions = get_enabled_regions(self.session)
            else:
                regions = regions.split()
            print(f'* - Now we are going to get all EC2 Instances in {regions} regions')
            headers = ['Region', 'Instance Name', 'Instance ID', 'Public IP', 'Metadata V1', 'SSH Key', 'IAM Role']
            data = []
            data.append(headers)
            for region in regions:
                ec2_client = self.session.client('ec2', region)
                try:
                    response = ec2_client.describe_instances()

                    if 'Reservations' in response:
                        reservations = response['Reservations']
                        for reservation in reservations:
                            instances = reservation['Instances']
                            for instance in tqdm(instances, desc=f"Processing {region} Region", unit="item"):
                                instance_id = instance['InstanceId']
                                ec2_instance = EC2Instance(self.session, instance_id, region)
                                ec2_instance_data = [region, ec2_instance.name, ec2_instance.instance_id,
                                                     ec2_instance.public_ip, ec2_instance.instance_metadata_v1,
                                                     ec2_instance.ssh_key, ec2_instance.iam_role]
                                data.append(ec2_instance_data)
                except Exception as e:
                    continue
            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - Acquire Instance Profile':
            print('* - Ok, we need to know the EC2 instanceID to Get the Instance Profile Data')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.acquire_EC2_instance_profile(self.session)
            print(f'* The EC2 Instance ID {instance_id} instance profile is: "{ec2_instance.instance_profile_arn}"')

        if ir_choice == 'AWS - Remove Instance Profile':
            print('* - Ok, we need to know the EC2 instanceID to remove the Instance Profile')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id)
            ec2_instance.acquire_EC2_instance_profile(self.session, self.region)
            ec2_instance.removeInstanceProfile(self.session)

        if ir_choice == 'AWS - Acquire EC2 Volume Image (Snapshot)':
            print('* - Ok, we need to know the EC2 instanceID to Get the volume image')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.acquire_ec2_volume_images(self.session)

        if ir_choice == 'AWS - Enable EC2 termination protection':
            print('* - Ok, we need to know the EC2 instanceID to Protect')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.enable_ec2_termination_protection(self.session)

        if ir_choice == 'AWS - TAG EC2 instance for Forensics':
            print('* - Ok, we need to know the EC2 instanceID to TAG')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.tag_ec2_instance(self.session)

        if ir_choice == 'AWS - Isolate EC2 Instance':
            print('* - Ok, we need to know the EC2 instanceID to isolate')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.isolate_ec2_instance(self.session)

        if ir_choice == 'AWS - Get EC2 Security Groups':
            print('* - Ok, we need to know the EC2 instanceID ID you want to get the Security Groups from')
            instance_id = input('EC2 Instance ID: ')
            headers = ['Instance ID', 'Security Group ID', 'Security Group Name', 'From Port', 'IP Range', 'To Port']
            data = []
            data.append(headers)
            ec2_instance = EC2Instance(self.session, instance_id)
            ec2_instance.isolate_ec2_instance(self.session, self.region)
            for sg in ec2_instance.security_groups:
                for rules in sg.rules:

                    try:
                        from_port = rules['FromPort']
                    except Exception as e:
                        from_port = None

                    try:
                        cidr = rules['IpRanges'][0]['CidrIp']
                    except Exception as e:
                        cidr = None

                    try:
                        to_port = rules['ToPort']
                    except Exception as e:
                        to_port = None

                    sg_data = [instance_id, sg.group_id, sg.group_name, from_port, cidr,
                               to_port]
                    data.append(sg_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - Terminate EC2 Instance':
            print('* - Ok, we need to know the EC2 instanceID to terminate')
            instance_id = input('EC2 Instance ID: ')
            ec2_instance = EC2Instance(self.session, instance_id, self.region)
            ec2_instance.terminate_ec2_instance(self.session)


        if ir_choice == 'AWS - Back':
            pass

    def do_Lambda(self, arg):
        ir_options = ['AWS - List All Lambda Functions', 'AWS - Get lambda Data (Env Var and Roles)',
                      'AWS - Remove Lambda Role', 'AWS - Delete Lambda Function', 'AWS - Back']
        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)

        if ir_choice == 'AWS - List All Lambda Functions':
            regions = input('AWS Regions (Space Separated, default us-east-1): ')
            if regions == '':
                regions = ['us-east-1']
            elif regions == '*':
                regions = get_enabled_regions(self.session)
            else:
                regions = regions.split()
            headers = ['Region', 'Function Name', 'Function Role', 'Env Vars']
            data = []
            data.append(headers)
            for region in regions:
                lambda_client = self.session.client('lambda', region)
                response = lambda_client.list_functions()
                if response['Functions']:
                    functions = response['Functions']
                    for function in tqdm(functions, desc=f"Processing {region} Region", unit="item"):
                        function_name = function['FunctionName']
                        lambda_function = LambdaFunction(self.session, function_name, region)
                        lambda_data = [region, lambda_function.function_name, lambda_function.role_arn,
                                       lambda_function.environment_variables]
                        data.append(lambda_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)

        if ir_choice == 'AWS - Get lambda Data (Env Var and Roles)':
            function_name = input('Lambda Function Name: ')
            data = []
            headers = ['Function Name', 'Function Role', 'Env Vars']
            data.append(headers)
            print(f'* - Now we are getting {function_name} lambda function env vars: ')
            try:
                lambda_function = LambdaFunction(self.session, function_name, self.region)
                lambda_data = [lambda_function.function_name, lambda_function.role_arn,
                               lambda_function.environment_variables]
                data.append(lambda_data)
                table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
                print(table)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Remove Lambda Role':
            function_name = input('Lambda Function Name: ')
            print(f'* - Now we are going to remove {function_name} lambda role: ')
            try:
                lambda_function = LambdaFunction(self.session, function_name, self.region)
                lambda_function.remove_lambda_roles(lambda_function.function_name, self.session)
            except Exception as e:
                print(e)

            print()

        if ir_choice == 'AWS - Delete Lambda Function':
            function_name = input('Lambda Function Name: ')
            print(f'* - Now we are going to remove {function_name} lambda function: ')
            try:
                lambda_function = LambdaFunction(self.session, function_name, self.region)
                lambda_function.delete_lambda(lambda_function.function_name, self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Back':
            pass

    def do_S3(self, arg):
        ir_options = ['AWS - S3 Get Buckets', 'AWS - S3 Get Public Buckets', 'AWS - S3 Get Public Objects from Bucket',
                      'AWS - S3 Block S3 Public Access', 'AWS - S3 Block S3 Public Object', 'AWS - Back']
        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)

        if ir_choice == 'AWS - S3 Get Buckets':
            headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date']
            data = []
            data.append(headers)
            print('* - Now we are going to Get Public S3 buckets')
            s3_client = self.session.client('s3')
            response = s3_client.list_buckets()
            if 'Buckets' in response:
                buckets = response['Buckets']
                for bucket in tqdm(buckets, desc="Processing", unit="item"):
                    bucket_name = bucket['Name']
                    s3_bucket = S3Bucket(self.session, bucket_name)
                    s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date]
                    data.append(s3_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - S3 Get Public Buckets':
            headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date']
            data = []
            data.append(headers)
            print('* - Now we are going to Get Public S3 buckets')
            s3_client = self.session.client('s3')
            response = s3_client.list_buckets()
            if 'Buckets' in response:
                buckets = response['Buckets']
                for bucket in tqdm(buckets, desc="Processing", unit="item"):
                    bucket_name = bucket['Name']
                    s3_bucket = S3Bucket(self.session, bucket_name)
                    if not s3_bucket.block_public_access:
                        s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date]
                        data.append(s3_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - S3 Get Public Objects from Bucket':
            bucket_name = input('S3 Bucket: ')
            print(f'* - Now we are going to retrieve public objects from the {bucket_name} s3 bucket')
            try:
                s3_bucket = S3Bucket(self.session, bucket_name)
                s3_bucket.get_public_objects(self.session)
                print(s3_bucket.public_objects)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - S3 Block S3 Public Access':
            bucket_name = input('S3 Bucket: ')
            print(f'* - Now we are going to block {bucket_name} s3 bucket public access')
            try:
                s3_bucket = S3Bucket(self.session, bucket_name)
                s3_bucket.block_s3_bucket_public_access(s3_bucket.bucket_name, self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - S3 Block S3 Public Object':
            bucket_name = input('S3 Bucket: ')
            object_key = input('Object Key: ')
            print(f'* - Now we are going to block {object_key} Object Key public access from {bucket_name} s3 bucket ')
            try:
                s3_bucket = S3Bucket(self.session, bucket_name)
                s3_bucket.block_s3_object_public_access(s3_bucket.bucket_name, object_key, self.session)
            except Exception as e:
                print(e)
            print()

        if ir_choice == 'AWS - Back':
            pass

    def do_EKS(self, arg):
        ir_options = ['AWS - List EKS Clusters', 'AWS - Get EKS Public Endpoint',
                      'AWS - Block EKS Public Access', 'AWS - Get EKS Log Status', 'AWS - Enable EKS Logs'
                      'AWS - Back']
        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)

        if ir_choice == 'AWS - List EKS Clusters':
            regions = input('AWS Regions (Space Separated, default us-east-1): ')
            if regions == '':
                regions = ['us-east-1']
            elif regions == '*':
                regions = get_enabled_regions(self.session)
            else:
                regions = regions.split()
            headers = ['Region', 'Clustter Name', 'Version', 'Endpoint', 'Role ARN', 'Logs']
            data = []
            data.append(headers)
            for region in regions:
                eks_client = self.session.client('eks', region)
                response = eks_client.list_clusters()
                if 'clusters' in response:
                    clusters = response['clusters']
                    for cluster in tqdm(clusters, desc=f"Processing {region} Region", unit="item"):
                        eks_cluster = EKSCluster(self.session, cluster, region)
                        eks_data = [region, eks_cluster.cluster_name, eks_cluster.version, eks_cluster.endpoint,
                                    eks_cluster.role_arn]
                        data.append(eks_data)
            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()


        if ir_choice == 'AWS - Get EKS Public Endpoint':
            cluster_name = input('EKS Cluster Name: ')
            print(f'* - Great, we are going to get the public endpoint status for {cluster_name}')
            eks_cluster = EKSCluster(self.session, cluster_name, self.region)
            print(eks_cluster.endpoint)
            print()

        if ir_choice == 'AWS - Block EKS Public Access':
            cluster_name = input('EKS Cluster Name: ')
            print(f'* - Great, we are going to get make {cluster_name} cluster endpoint private')
            eks_cluster = EKSCluster(self.session, cluster_name, self.region)
            eks_cluster.block_eks_public_endpoint(self.session)
            print()

        if ir_choice == 'AWS - Get EKS Log Status':
            cluster_name = input('EKS Cluster Name: ')
            print(f'* - Great, we are going to get {cluster_name} logs status')
            eks_cluster = EKSCluster(self.session, cluster_name, self.region)
            print(eks_cluster.log_status)
            print()

        if ir_choice == 'AWS - Enable EKS Logs':
            cluster_name = input('EKS Cluster Name: ')
            print(f'* - Great, we are going to get enable logs for {cluster_name} cluster')
            eks_cluster = EKSCluster(self.session, cluster_name, self.region)
            eks_cluster.enable_eks_logs(self.session)
            print()

        if ir_choice == 'AWS - Back':
            pass

    def do_RDS(self, arg):
        ir_options = ['AWS - Get RDS Databases', 'AWS - Get RDS Database Log Status',
                      'AWS - Get RDS DB Security Groups', 'AWS - Get RDS Database Public Access Status',
                      'AWS - Block RDS Public Access', 'AWS - Enable RDS Deletion Protection', 'AWS - Back']

        ir_choice = get_user_input('* - Tactical IR Options:', ir_options)
        if ir_choice == 'AWS - Get RDS Databases':
            regions = input('AWS Regions (Space Separated, default us-east-1): ')
            if regions == '':
                regions = ['us-east-1']
            elif regions == '*':
                regions = get_enabled_regions(self.session)
            else:
                regions = regions.split()
            headers = ['Region', 'Instance Identifier', 'Engine', 'Is Public', 'Logs', 'Delete Protection']
            data = []
            data.append(headers)
            for region in regions:
                rds_client = self.session.client('rds', region)
                response = rds_client.describe_db_instances()
                if response['DBInstances']:
                    db_instances = response['DBInstances']
                    for db_instance in tqdm(db_instances, desc=f"Processing {region} Region", unit="item"):
                        db_instance_id = db_instance['DBInstanceIdentifier']
                        rds_instance = RDSInstance(self.session, db_instance_id, region)
                        rds_data = [region, rds_instance.db_instance_identifier, rds_instance.engine, rds_instance.publicly_accessible,
                                    rds_instance.log_status, rds_instance.delete_protection]
                        data.append(rds_data)

            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - Get RDS Database Log Status':
            db_instance_id = input('RDS Database Name (DB Identifier): ')
            print(f'* - Now we are going to get the log status of the {db_instance_id} database:')
            rds_instance = RDSInstance(self.session, db_instance_id, self.region)
            print(rds_instance.log_status)

        if ir_choice == 'AWS - Get RDS Database Public Access Status':
            db_instance_id = input('RDS Database Name (DB Identifier): ')
            print(f'* - Now we are going to get the public access status of the {db_instance_id} database:')
            rds_instance = RDSInstance(self.session, db_instance_id, self.region)
            if rds_instance.publicly_accessible:
                print(f'* - Endpoint is PUBLIC')
            else:
                print(f'* - Endpoint is PRIVATE')
                print()

        if ir_choice == 'AWS - Block RDS Public Access':
            db_instance_id = input('RDS Database Name (DB Identifier): ')
            print(f'* - Now we are going to BLOCK the public access status for the {db_instance_id} database:')
            rds_instance = RDSInstance(self.session, db_instance_id, self.region)
            rds_instance.block_RDS_public_access(rds_instance.db_instance_identifier, self.session)
            print()

        if ir_choice == 'AWS - Enable RDS Deletion Protection':
            db_instance_id = input('RDS Database Name (DB Identifier): ')
            print(f'* - Now we are going to ENABLE delete protection for the {db_instance_id} database:')
            rds_instance = RDSInstance(self.session, db_instance_id, self.region)
            rds_instance.block_RDS_public_access(rds_instance.db_instance_identifier, self.session)
            print()

        if ir_choice == 'AWS - Get RDS DB Security Groups':
            headers = ['DB Instance ID', 'Security Group ID', 'Security Group Name', 'From Port', 'IP Range', 'To Port']
            data = []
            data.append(headers)
            db_instance_id = input('RDS Database Name (DB Identifier): ')
            print(f'* - Now we are going to get the {db_instance_id} database security groups:')
            rds_instance = RDSInstance(self.session, db_instance_id, self.region)
            for sg in rds_instance.security_groups:
                security_group = SecurityGroup.constructor(self.session, sg['VpcSecurityGroupId'], self.region)
                for rules in security_group.rules:

                    try:
                        from_port = rules['FromPort']
                    except Exception as e:
                        from_port = None

                    try:
                        cidr = rules['IpRanges'][0]['CidrIp']
                    except Exception as e:
                        cidr = None

                    try:
                        to_port = rules['ToPort']
                    except Exception as e:
                        to_port = None

                    sg_data = [db_instance_id, security_group.group_id, security_group.group_name, from_port, cidr, to_port]
                    data.append(sg_data)


            table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            print()

        if ir_choice == 'AWS - Back':
            pass


class CMDThreatHunting(cmd.Cmd):
    intro = "\n" \
            "Type 'help' for a list of commands. \n" \
            "- AWS: Get Dangerous API Calls from Event History \n" \
            "- IP: Useful tools for IP Analysis, like whois and Shodan (Shonda needs API KEY). \n" \
            "- VT: VirusTotal wrapper for IP, Domain, File and Hash analysis (Needs API KEY)"
    prompt = "Dredge - Threat Hunting: "

    def do_AWS(self, arg):
        """AWS Event History API Call search for dangerous API Calls"""
        print()
        start_date = input('Start Date <2023-03-01>: ')
        end_date = input('End Date <2023-04-01>: ')
        profile = input('AWS Profile: ')
        region = input('AWS Region: ')
        try:
            session = AWSAuth(profile, region).session
        except Exception as e:
            print(e)
            print()
            pass

        print()
        aws_options = ['AWS - Event History Dangerous API Calls',  'AWS - Event History Dangerous IP IoC', 'AWS - Back']
        aws_choice = get_user_input('* - Great, these are the options for AWS Threat Hunting', aws_options)

        if aws_choice == 'AWS - Event History Dangerous API Calls':
            try:
                get_event_history_alerts(session, start_date, end_date)
            except KeyboardInterrupt as e:
                print()
                return True

        if aws_choice == 'AWS - Event History Dangerous IP IoC':
            ips = input('List of IPs (Space separated): ')
            ioc_ips = ips.split()
            try:
                get_event_history_alerts(session, start_date, end_date, ioc_ips)
            except KeyboardInterrupt as e:
                print()
                return True

        if aws_choice == 'AWS - Back':
            print()
            pass

    def do_IP(self, arg):
        """Utils to get IPs from files or for IP enrichment using Shodan or Whois"""
        th_options = ['IP - Get IPs from File', 'IP - Whois from file', 'IP - Whois (input)',
                      'IP - Shodan (input)', 'IP - Shodan from file', 'IP - Back']
        th_choice = get_user_input('* - Great, these are the options for IP Enrichment', th_options)
        threat_hunting = ThreatHunting()

        if th_choice == 'IP - Get IPs from File':
            print('- Awesome, we need to select a file to retrieve IPs from')
            file_to_scan = input('File: ')
            print()
            threat_hunting.ip_retriever(file_to_scan)
            print(threat_hunting.ips)

        if th_choice == 'IP - Whois (input)':
            ip_to_enrich = input('IP to Enrich: ')
            print()
            match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_to_enrich)
            if match:
                threat_hunting.whois_enrichment(ip_to_enrich)

            else:
                print('Wrong IP format, please try again')

        if th_choice == 'IP - Whois from file':
            print('* - Awesome, we need to select a file to get IPs from and enrich with whois')
            file_to_scan = input('File: ')
            print()
            ips = threat_hunting.ip_retriever(file_to_scan)
            for ip in ips:
                threat_hunting.whois_enrichment(ip)

        if th_choice == 'IP - Shodan (input)':
            ip_to_enrich = input('IP to Enrich: ')
            shodan_api_key = input ('Shodan API Key: ')
            print()
            shodan_enrichment(ip_to_enrich, shodan_api_key)
            print()

        if th_choice == 'IP - Shodan from file':
            if os.getenv('SHODAN_KEY'):
                shodan_api_key = os.getenv('SHODAN_KEY')
            else:
                shodan_api_key = input('Shodan API Key: ')
                os.environ['VT_KEY'] = shodan_api_key

            file_to_scan = input('File: ')
            ips = threat_hunting.ip_retriever(file_to_scan)
            print()
            print(f'IPs to Analyze: {len(ips)}')
            print(ips)
            print()
            counter = 1
            hosts = []
            for ip_to_enrich in ips:
                print(f'{counter}) IP: {ip_to_enrich}')
                hosts.append(shodan_enrichment(ip_to_enrich, shodan_api_key))
                counter += 1
            
            print(hosts)

        if th_choice == 'IP - Back':
            print()
            pass

    def do_VT(self, arg):
        '''Util for file, IP and domain analysis using VirusTotal API; API KEY Needed'''
        vt_options = ['VT - VirusTotal from file', 'VT - VirusTotal from IP', 'VT - VirusTotal from Domain',
                      'VT - VirusTotal from Hash', 'VT - Back']

        vt_choice = get_user_input('* - Great, these are the options for VirusTotal Analysis', vt_options)

        if vt_choice == 'VT - VirusTotal from file':
            if os.getenv('VT_KEY'):
                vt_api_key = os.getenv('VT_KEY')
            else:
                vt_api_key = input('VirusTotal API KEY: ')
                os.environ['VT_KEY'] = vt_api_key
            file_to_scan = input('File: ')
            print()
            try:
                vt_analyze_file(vt_api_key, file_to_scan)
            except KeyboardInterrupt as e:
                pass
            print()

        if vt_choice == 'VT - VirusTotal from IP':
            if os.getenv('VT_KEY'):
                vt_api_key = os.getenv('VT_KEY')
            else:
                vt_api_key = input('VirusTotal API KEY: ')
                os.environ['VT_KEY'] = vt_api_key
            ip_to_scan = input('IP: ')
            print()
            try:
                vt_analyze_ip(vt_api_key, ip_to_scan)
            except KeyboardInterrupt as e:
                pass
            print()

        if vt_choice == 'VT - VirusTotal from Domain':
            if os.getenv('VT_KEY'):
                vt_api_key = os.getenv('VT_KEY')
            else:
                vt_api_key = input('VirusTotal API KEY: ')
                os.environ['VT_KEY'] = vt_api_key
            domain_to_scan = input('Domain Name: ')
            print()
            try:
                vt_analyze_domain(vt_api_key, domain_to_scan)
            except KeyboardInterrupt as e:
                pass
            print()

        if vt_choice == 'VT - VirusTotal from Hash':
            if os.getenv('VT_KEY'):
                vt_api_key = os.getenv('VT_KEY')
            else:
                vt_api_key = input('VirusTotal API KEY: ')
                os.environ['VT_KEY'] = vt_api_key
            hash_to_scan = input('Hash: ')
            print()
            try:
                vt_analyze_hash(vt_api_key, hash_to_scan)
            except KeyboardInterrupt as e:
                pass
            print()

        if vt_choice == 'VT - Back':
            print()
            pass


def get_user_input(prompt, options):
    while True:
        print(prompt)
        for i, option in enumerate(options):
            print(f"{i + 1}. {option}")
        print()
        choice = input("Enter your choice: ")

        if not choice.isdigit():
            print("Invalid choice. Please enter a number.")
            continue

        choice = int(choice)

        if choice < 1 or choice > len(options):
            print("Invalid choice. Please select a valid option.")
            continue

        return options[choice - 1]


def get_enabled_regions(session):
    ec2_client = session.client('ec2')
    response = ec2_client.describe_regions()

    enabled_regions = []
    for region in response['Regions']:
        region_name = region['RegionName']
        enabled_regions.append(region_name)

    return enabled_regions