from modules.class_aws_iam_user import IAMUser
from modules.class_aws_iam_role import IAMRole
from modules.class_aws_iam_group import IAMGroup
from modules.class_aws_ec2_instance import EC2Instance
from modules.class_aws_lambda import LambdaFunction
from modules.class_aws_eks import EKSCluster
from modules.class_aws_s3_bucket import S3Bucket
from modules.class_aws_rds_instance import RDSInstance
from modules.class_aws_cloudwatch_logs import CloudWatchLogGroup
from tqdm import tqdm
from tabulate import tabulate


class AWSAccount:
    def __init__(self, account_name, account_alias, account_id, created_date, iam_users, iam_roles, iam_groups,
                 ec2_instances, lambda_functions, eks_clusters, s3_buckets, rds_instances, current_region, regions, session):

        self.account_id = account_id or None
        self.account_name = account_name or None
        self.account_alias = account_alias or None
        self.current_region = current_region or None
        self.created_date = created_date or None
        self.iam_users = iam_users or None
        self.iam_roles = iam_roles or None
        self.iam_groups = iam_groups or None
        self.ec2_instances = ec2_instances or None
        self.lambda_functions = lambda_functions or None
        self.eks_clusters = eks_clusters or None
        self.s3_buckets = s3_buckets or None
        self.rds_instances = rds_instances or None
        self.regions = regions
        self.session = session

    @classmethod
    def constructor(cls, session):
        iam_client = session.client('iam')
        current_region = session.region_name

        # Get account information from IAM
        response = iam_client.list_account_aliases()
        account_alias = response.get('AccountAliases', [])

        # Get account name and ARN
        account_summary = iam_client.get_account_summary()
        try:
            account_name = account_summary['SummaryMap']['AccountName']
        except KeyError as e:
            account_name = ''

        # Account ARN
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')

        # Get account created date
        account_info = iam_client.get_account_authorization_details(Filter=['User'])
        created_date = account_info['UserDetailList'][0]['CreateDate']

        regions = cls.get_enabled_regions(session)
        ec2_instances = []
        lambda_functions = []
        eks_clusters = []
        rds_instances = []
        for region in regions:
            ec2_instances.append(cls.get_ec2_instances(session, region))
        for region in regions:
            lambda_functions.append(cls.get_lambda_functions(session, region))
        for region in regions:
            eks_clusters.append(cls.get_eks_clusters(session, region))
        for region in regions:
            rds_instances.append(cls.get_rds_instances(session, region))

        # GET IAM ENTITIES:

        iam_users = cls.get_iam_users(session)
        #iam_roles = cls.get_iam_roles(session)
        #iam_groups = cls.get_iam_groups(session)
        iam_roles = []
        iam_groups = []
        # S3 BUCKETS:
        s3_buckets = cls.get_s3_buckets(session)

        return cls(account_name, account_alias, account_id, created_date, iam_users, iam_roles, iam_groups,
                   ec2_instances, lambda_functions, eks_clusters, s3_buckets, rds_instances, current_region,
                   regions, session)

    @classmethod
    def get_iam_users(cls, session):
        iam_client = session.client('iam')
        response = iam_client.list_users()
        iam_users = []
        if 'Users' in response:
            users = response['Users']
            for user in tqdm(users, desc="Processing IAM Users", unit="item"):
                user_name = user['UserName']
                iam_users.append(IAMUser(session, user_name))

        return iam_users

    @classmethod
    def get_iam_roles(cls, session):
        iam_client = session.client('iam')
        response = iam_client.list_roles()

        iam_roles = []
        if 'Roles' in response:
            roles = response['Roles']
            for role in tqdm(roles, desc="Processing IAM Roles", unit="item"):
                role_name = role['RoleName']
                iam_roles.append(IAMRole(session, role_name))

        return iam_roles

    @classmethod
    def get_iam_groups(cls, session):
        iam_client = session.client('iam')

        response = iam_client.list_groups()
        iam_groups = []
        if 'Groups' in response:
            groups = response['Groups']
            for group in tqdm(groups, desc="Processing IAM Groups", unit="item"):
                group_name = group['GroupName']
                iam_groups.append(IAMGroup(session, group_name))

        return iam_groups

    @classmethod
    def get_ec2_instances(cls, session, region):
        ec2_client = session.client('ec2', region)
        response = ec2_client.describe_instances()

        if 'Reservations' in response:
            ec2_instances = []
            reservations = response['Reservations']
            for reservation in reservations:
                instances = reservation['Instances']
                for instance in tqdm(instances, desc=f"Processing EC2 in {region}", unit="item"):
                    instance_id = instance['InstanceId']
                    ec2_instances.append(EC2Instance(session, instance_id, region))
            return ec2_instances

    @classmethod
    def get_lambda_functions(cls, session, region):
        lambda_client = session.client('lambda')

        response = lambda_client.list_functions()
        lambda_functions = []
        if response['Functions']:
            functions = response['Functions']
            for function in tqdm(functions, desc=f"Processing Lambda in {region}", unit="item"):
                function_name = function['FunctionName']
                lambda_functions.append(LambdaFunction(session, function_name))
        return lambda_functions

    @classmethod
    def get_eks_clusters(cls, session, region):
        eks_client = session.client('eks', region)

        response = eks_client.list_clusters()
        eks_clusters = []
        if response['clusters']:
            clusters = response['clusters']
            for cluster in tqdm(clusters, desc=f"Processing EKS Clusters in {region}", unit="item"):
                eks_clusters.append(EKSCluster(session, cluster, region))
        return eks_clusters

    @classmethod
    def get_s3_buckets(cls, session):
        s3_client = session.client('s3')

        response = s3_client.list_buckets()
        s3_buckets = []
        if 'Buckets' in response:
            buckets = response['Buckets']
            for bucket in tqdm(buckets, desc="Processing S3 Buckets", unit="item"):
                bucket_name = bucket['Name']
                s3_buckets.append(S3Bucket(session, bucket_name))
        return s3_buckets

    @classmethod
    def get_rds_instances(cls, session, region):
        rds_client = session.client('rds', region)

        response = rds_client.describe_db_instances()
        rds_instances = []
        if response['DBInstances']:
            db_instances = response['DBInstances']
            for db_instance in tqdm(db_instances, desc=f"Processing RDS in {region}", unit="item"):
                db_instance_id = db_instance['DBInstanceIdentifier']
                rds_instances.append(RDSInstance(session, db_instance_id, region))
        return rds_instances

    @classmethod
    def get_cloudwatch_log_groups(cls, session, region):
        client = session.client('logs', region)
        response = client.describe_log_groups()
        log_groups = response.get('logGroups', [])
        logs = []
        while 'nextToken' in response:
            next_token = response['nextToken']
            response = client.describe_log_groups(nextToken=next_token)
            log_groups.extend(response.get('logGroups', []))

        print('- Cloudwatch Log Groups: ')
        for log_group in tqdm(log_groups, desc="Processing", unit="item"):
            logs.append(CloudWatchLogGroup.constructor(session, log_group['logGroupName'], region))

        return logs

    @classmethod
    def get_enabled_regions(cls, session):
        ec2_client = session.client('ec2')
        response = ec2_client.describe_regions()

        enabled_regions = []
        for region in response['Regions']:
            region_name = region['RegionName']
            enabled_regions.append(region_name)

        return enabled_regions

    def reporter(self):
        user_headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
        user_data = []
        user_data.append(user_headers)
        ec2_headers = ['Region', 'Instance Name', 'Instance ID', 'Public IP', 'Metadata V1', 'SSH Key', 'IAM Role']
        ec2_data = []
        ec2_data.append(ec2_headers)
        lambda_headers = ['Region', 'Function Name', 'Function Role', 'Env Vars']
        lambda_data = []
        lambda_data.append(lambda_headers)
        eks_headers = ['Region', 'Clustter Name', 'Version', 'Endpoint', 'Role ARN', 'Logs']
        eks_data = []
        eks_data.append(eks_headers)
        rds_headers = ['Region', 'Instance Identifier', 'Engine', 'Is Public', 'Logs', 'Delete Protection']
        rds_data = []
        rds_data.append(rds_headers)
        s3_headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date']
        s3_data = []
        s3_data.append(s3_headers)


        for iam_user in self.iam_users:
            for i in iam_user.access_keys:
                formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
                access_key_data = [i['AccessKeyId'], i['Status'], iam_user.user_name, formatted_dt]
                user_data.append(access_key_data)

        for ec2_instance in self.ec2_instances:
            ec2_instance_data = [ec2_instance.region, ec2_instance.name, ec2_instance.instance_id,
                                 ec2_instance.public_ip, ec2_instance.instance_metadata_v1,
                                 ec2_instance.ssh_key, ec2_instance.iam_role]
            ec2_data.append(ec2_instance_data)

        for lambda_function in self.lambda_functions:
            lambda_data = [lambda_function.region, lambda_function.function_name, lambda_function.role_arn,
                           lambda_function.environment_variables]
            lambda_data.append(lambda_data)

        for eks_cluster in self.eks_clusters:
            eks_data = [eks_cluster.region, eks_cluster.cluster_name, eks_cluster.version, eks_cluster.endpoint,
                        eks_cluster.role_arn]
            eks_data.append(eks_data)

        for s3_bucket in self.s3_buckets:
            s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date]
            s3_data.append(s3_data)

        for rds_instance in self.rds_instances:
            rds_data = [rds_instance.region, rds_instance.db_instance_identifier, rds_instance.engine,
                        rds_instance.publicly_accessible,
                        rds_instance.log_status, rds_instance.delete_protection]
            rds_data.append(rds_data)

        account = [self.account_id, self.account_name, self.account_alias, self.current_region, self.created_date]
        iam_user_table = tabulate(user_data, headers="firstrow", tablefmt="fancy_grid")
        print(iam_user_table)
        print()

        ec2_table = tabulate(ec2_data, headers="firstrow", tablefmt="fancy_grid")
        print(ec2_table)
        print()

        lambda_table = tabulate(lambda_data, headers="firstrow", tablefmt="fancy_grid")
        print(lambda_table)
        print()

        eks_table = tabulate(eks_data, headers="firstrow", tablefmt="fancy_grid")
        print(eks_table)
        print()

        s3_table = tabulate(s3_data, headers="firstrow", tablefmt="fancy_grid")
        print(s3_table)
        print()

        rds_table = tabulate(rds_data, headers="firstrow", tablefmt="fancy_grid")
        print(rds_table)
        print()
