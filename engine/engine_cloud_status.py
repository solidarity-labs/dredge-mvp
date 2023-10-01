import botocore
from modules.class_aws_iam_user import IAMUser
from modules.class_aws_iam_group import IAMGroup
from modules.class_aws_iam_role import IAMRole
from modules.class_aws_lambda import LambdaFunction
from modules.class_aws_s3_bucket import S3Bucket
from modules.class_aws_rds_instance import RDSInstance
from modules.class_aws_security_group import SecurityGroup
from modules.class_aws_eks import EKSCluster
from modules.class_aws_ec2_instance import EC2Instance
from engine.engine_reporter import reporter

flag = "tabulated"

def get_iam_users(session, reporter_flag):
    file_name = 'iam_users'
    iam_client = session.client('iam')
    response = iam_client.list_users()
    headers = ['User Name', 'AccessKeys', 'MFA Status', 'Has Console Access', 'Creation Date']
    data = []
    data.append(headers)
    if 'Users' in response:
        users = response['Users']
        for user in users:
            access_keys = []
            user_name = user['UserName']
            iam_user = IAMUser(session, user_name)
            for i in iam_user.access_keys:
                access_keys.append(i['AccessKeyId'])
            formated_dt = iam_user.create_date.strftime("%B %d, %Y %H:%M:%S %p")
            iam_user_data = [iam_user.user_name, access_keys, iam_user.mfa, iam_user. login_profile, formated_dt]
            data.append(iam_user_data)

        reporter(data, reporter_flag, file_name)


def get_access_keys(session, reporter_flag):
    file_name = 'access_keys'
    iam_client = session.client('iam')
    response = iam_client.list_users()
    headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
    data = []
    data.append(headers)
    if 'Users' in response:
        users = response['Users']
        for user in users:
            access_keys = []
            user_name = user['UserName']
            iam_user = IAMUser(session, user_name)
            for i in iam_user.access_keys:
                formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
                access_key_data = [i['AccessKeyId'], i['Status'], user_name, formatted_dt]
                data.append(access_key_data)
    
    reporter(data, reporter_flag, file_name)


def get_user_access_keys(session, user_name, reporter_flag):
    file_name = 'user_access_keys'
    headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
    data = []
    data.append(headers)

    iam_user = IAMUser(session, user_name)
    for i in iam_user.access_keys:
        formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
        access_key_data = [i['AccessKeyId'], i['Status'], user_name, formatted_dt]
        data.append(access_key_data)
            
    reporter(data, reporter_flag, file_name)


def get_ec2_instances(session, regions, reporter_flag):
    file_name = 'ec2_instances'
    headers = ['Region', 'Instance Name', 'Instance ID', 'Public IP', 'Metadata V1', 'SSH Key', 'IAM Role']
    data = []
    data.append(headers)
    for region in regions:
        try:
            ec2_client = session.client('ec2', region)
            try:
                response = ec2_client.describe_instances()
                if 'Reservations' in response:
                    reservations = response['Reservations']
                    for reservation in reservations:
                        instances = reservation['Instances']
                        for instance in instances:
                            instance_id = instance['InstanceId']
                            ec2_instance = EC2Instance(session, instance_id, region)
                            ec2_instance_data = [region, ec2_instance.name, ec2_instance.instance_id,
                                                ec2_instance.public_ip, ec2_instance.instance_metadata_v1,
                                                ec2_instance.ssh_key, ec2_instance.iam_role]
                            data.append(ec2_instance_data)

            except botocore.exceptions.ClientError as e:
                continue
        except Exception as e:
            continue

    reporter(data, reporter_flag, file_name)


def get_security_groups(session, instance_id, region, reporter_flag):
    file_name = 'ec2_security_groups'
    headers = ['Instance ID', 'Security Group ID', 'Security Group Name', 'From Port', 'IP Range', 'To Port']
    data = []
    data.append(headers)
    ec2_instance = EC2Instance(session, instance_id, region)

    for sg in ec2_instance.security_groups:
        if sg.rules:
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

                if from_port == None and cidr == None and to_port == None and rules['IpProtocol'] == '-1':
                    from_port = 'all'
                    cidr = '0.0.0.0/0'
                    to_port = 'all'


                sg_data = [instance_id, sg.group_id, sg.group_name, from_port, cidr,
                            to_port]
        
        else:
            sg_data = [instance_id, sg.group_id, sg.group_name, None, None, None]
        
        data.append(sg_data)
    
    reporter(data, reporter_flag, file_name)


def get_lambda_functions(session, regions, reporter_flag):
    file_name = 'lambda_functions'
    headers = ['Region', 'Function Name', 'Function Role', 'Env Vars']
    data = []
    data.append(headers)
    for region in regions:
        try:
            lambda_client = session.client('lambda', region)
            response = lambda_client.list_functions()
            if response['Functions']:
                functions = response['Functions']
                for function in functions:
                    function_name = function['FunctionName']
                    lambda_function = LambdaFunction(session, function_name, region)
                    lambda_data = [region, lambda_function.function_name, lambda_function.role_arn,
                                lambda_function.environment_variables]
                    data.append(lambda_data)
        except botocore.exceptions.ClientError as e:
                continue

    reporter(data, reporter_flag, file_name)


def get_lambda_data(session, function_name, region, reporter_flag):
    file_name = 'lambda_data'
    data = []
    headers = ['Function Name', 'Function Role', 'Env Vars']
    data.append(headers)
    try:
        lambda_function = LambdaFunction(session, function_name, region[0])
        lambda_data = [lambda_function.function_name, lambda_function.role_arn,
                        lambda_function.environment_variables]
        
        data.append(lambda_data)
        reporter(data, reporter_flag, file_name)
    except Exception as e:
        print(e)


def get_buckets(session, reporter_flag):
    file_name = 's3_buckets'
    headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date']
    data = []
    data.append(headers)
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    if 'Buckets' in response:
        buckets = response['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            s3_bucket = S3Bucket(session, bucket_name)
            s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date]
            data.append(s3_data)

    reporter(data, reporter_flag, file_name)


def get_public_buckets(session, reporter_flag):
    file_name = 'public_s3_buckets'
    headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date']
    data = []
    data.append(headers)
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    if 'Buckets' in response:
        buckets = response['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            s3_bucket = S3Bucket(session, bucket_name)
            if not s3_bucket.block_public_access:
                s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date]
                data.append(s3_data)

    reporter(data, reporter_flag, file_name)


def get_public_objects(session, bucket_name, reporter_flag):
    file_name = 'public_objects'
    headers = ['Public Object', 'Bucket Name', 'Bucket Creation Date', 'Object Creation Date']
    data = []
    data.append(headers)

    try:
        s3_bucket = S3Bucket(session, bucket_name)
        s3_bucket.get_public_objects(session)
        for object in s3_bucket.public_objects:
            s3_data = [object['key'], bucket_name, s3_bucket.creation_date, object['LastModified']]
            data.append(s3_data)

    except Exception as e:
        print(e)

    reporter(data, reporter_flag, file_name)
    

def get_all_public_objects(session, reporter_flag):
    file_name = 'all_public_objects'
    headers = ['Bucket Name', 'Block Public Access Status', 'Creation Date', 'Public Object', 'Object Creation Date']
    data = []
    data.append(headers)
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    if 'Buckets' in response:
        buckets = response['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            s3_bucket = S3Bucket(session, bucket_name)
            s3_bucket.get_public_objects(session)
            for object in s3_bucket.public_objects:
                s3_data = [s3_bucket.bucket_name, s3_bucket.block_public_access, s3_bucket.creation_date, object['key'], object['LastModified']]
                data.append(s3_data)
    
    reporter(data, reporter_flag, file_name)


def get_eks_clusters(session, regions, reporter_flag):
    file_name = 'eks_clusters'
    headers = ['Region', 'Clustter Name', 'Version', 'Endpoint', 'Role ARN', 'Logs']
    data = []
    data.append(headers)
    for region in regions:
        try:
            eks_client = session.client('eks', region)
            response = eks_client.list_clusters()
            if 'clusters' in response:
                clusters = response['clusters']
                for cluster in clusters:
                    eks_cluster = EKSCluster(session, cluster, region)
                    eks_data = [region, eks_cluster.cluster_name, eks_cluster.version, eks_cluster.endpoint,
                                eks_cluster.role_arn]
                    data.append(eks_data)
        except Exception as e:
            continue

    reporter(data, reporter_flag, file_name)


def get_eks_public_endpoints(session, cluster_name, region):
    region = region [0]
    eks_cluster = EKSCluster(session, cluster_name, region)
    print(eks_cluster.endpoint)


def get_eks_log_status(session, cluster_name, regions):
    eks_cluster = EKSCluster(session, cluster_name, regions[0])
    print(eks_cluster.log_status)


def get_rds_databases(session, regions, reporter_flag):
    file_name = 'rds_databases'
    headers = ['Region', 'Instance Identifier', 'Engine', 'Is Public', 'Logs', 'Delete Protection']
    data = []
    data.append(headers)
    for region in regions:
        try:
            rds_client = session.client('rds', region)
            response = rds_client.describe_db_instances()
            if response['DBInstances']:
                db_instances = response['DBInstances']
                for db_instance in db_instances:
                    db_instance_id = db_instance['DBInstanceIdentifier']
                    rds_instance = RDSInstance(session, db_instance_id, region)
                    rds_data = [region, rds_instance.db_instance_identifier, rds_instance.engine, rds_instance.publicly_accessible,
                                rds_instance.log_status, rds_instance.delete_protection]
                    data.append(rds_data)
        except Exception as e:
            continue

    reporter(data, reporter_flag, file_name)


def get_rds_log_status(session, db_instance_id, regions):
    rds_instance = RDSInstance(session, db_instance_id, regions[0])
    print(rds_instance.log_status)


def get_rds_security_groups(session, db_instance_id, regions, reporter_flag):
    file_name = 'rds_security_groups'
    headers = ['DB Instance ID', 'Security Group ID', 'Security Group Name', 'From Port', 'IP Range', 'To Port']
    data = []
    data.append(headers)
    rds_instance = RDSInstance(session, db_instance_id, regions[0])
    for sg in rds_instance.security_groups:
        security_group = SecurityGroup.constructor(session, sg['VpcSecurityGroupId'], regions[0])
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


    reporter(data, reporter_flag, file_name)


def get_rds_public_access(session, db_instance_id, regions):
    rds_instance = RDSInstance(session, db_instance_id, regions[0])
    if rds_instance.publicly_accessible:
        print(f'Endpoint is PUBLIC')
    else:
        print(f'Endpoint is PRIVATE')


def get_all_aws(session, regions, reporter_flag):
    print(['IAM Users'])
    get_iam_users(session, reporter_flag)

    print(['EC2 Instances'])
    get_ec2_instances(session, regions, reporter_flag)

    print(['Lambda Functions'])
    get_lambda_functions(session, regions, reporter_flag)
    
    print(['Public S3 Buckets'])
    get_public_buckets(session, reporter_flag)

    print(['EKS Clusters'])
    get_eks_clusters(session, regions, reporter_flag)

    print(['RDS Databases'])
    get_rds_databases(session, regions, reporter_flag)

