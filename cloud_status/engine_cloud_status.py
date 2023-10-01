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
from engine.engine_reporter import Reporter
from modules.class_k8s_cluster import KubernetesCluster
import base64

        
# K8S CLOUD STATUS
def get_namespaces():
    k8s = KubernetesCluster()
    namespaces = k8s.list_namespaces()
    print(namespaces)


def get_pods(csv, json, tabulated, namespace):
    file_name = 'pods'
    k8s = KubernetesCluster()
    headers = ['Namespace', 'Pod Name']
    data = []
    data.append(headers)
    pod_data = []
    if namespace == "*":
        namespaces = k8s.list_namespaces()
        for namespace in namespaces:
            pods = k8s.list_pods(namespace)
            for pod in pods:
                pod_data = [namespace, pod]
                data.append(pod_data)
    else:
        pods = k8s.list_pods(namespace)
        for pod in pods:
            pod_data = [namespace, pod]
            data.append(pod_data)
    
    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()
    #reporter(data, reporter_flag, file_name)


def get_secrets(csv, json, tabulated, namespace):
    file_name = 'secrets'
    k8s = KubernetesCluster()
    headers = ['Namespace', 'Secret Name', 'Secret', 'Secret Content (Base64)']
    data = []
    secret_content_list = []
    data.append(headers)
    
    if namespace == "*":
        namespaces = k8s.list_namespaces()
        for namespace in namespaces:
            secrets = k8s.list_secrets(namespace)
            for secret in secrets:
                secret_content = k8s.get_secret_data(namespace, secret)
                for key in secret_content.keys():
                    decoded_secret = base64.b64decode(secret_content[key])
                    secret_content_list = [namespace, secret, key, decoded_secret[0:20]]
                    data.append(secret_content_list)
    else:
        secrets = k8s.list_secrets(namespace)
        for secret in secrets:
            secret_content = k8s.get_secret_data(namespace, secret)
            for key in secret_content.keys():
                decoded_secret = base64.b64decode(secret_content[key])
                secret_content_list = [namespace, secret, key, decoded_secret[0:20]]
                data.append(secret_content_list)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_all_services_accounts(csv, json, tabulated, namespace):
    file_name = 'service_accounts'
    k8s = KubernetesCluster()
    data = []
    headers = ['Namespace', 'Service Account Name', 'Role Type', 'Role Name']
    data.append(headers)
    if namespace == '*':
        namespaces = k8s.list_namespaces()
    else:
        namespaces = [namespace]
    
    for namespace in namespaces:
        service_accounts = k8s.list_service_accounts(namespace)
        for sa in service_accounts:
            roles = k8s.get_roles_for_service_account(namespace, sa)
            if roles:
                for role in roles:
                    role_list = [namespace, sa, role['type'], role['name']]
                    data.append(role_list)
            else:
                role_list = [namespace, sa, None, None]
                data.append(role_list)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_all_services_accounts_with_permissions(csv, json, tabulated, namespace):
    file_name = 'service_accounts_with_permissions'
    k8s = KubernetesCluster()
    data = []
    headers = ['Namespace', 'Service Account Name', 'Role Type', 'Role Name', 'Resources', 'Verbs']
    data.append(headers)
    if namespace == '*':
        namespaces = k8s.list_namespaces()
    else:
        namespaces = [namespace]
    
    for namespace in namespaces:
        service_accounts = k8s.list_service_accounts(namespace)
        for sa in service_accounts:
            roles = k8s.get_roles_for_service_account(namespace, sa)
            if roles:
                for role in roles:
                    if role['type'] == 'role':
                        permissions = k8s.get_role_permissions(namespace, role['name'])
                        for i in permissions:                            
                            role_list = [namespace, sa, role['type'], role['name'],  i['resources'], i['verbs']]
                            data.append(role_list)
                            
                    elif role['type'] == 'clusterRole':
                        permissions = k8s.get_cluster_role_permissions(role['name'])
                        for i in permissions: 
                            role_list = [namespace, sa, role['type'], role['name'],  i['resources'], i['verbs']]
                            data.append(role_list)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_roles_for_service_account(csv, json, tabulated, namespace, service_account_name):
    file_name = f'roles_for_sa_{service_account_name}'
    k8s = KubernetesCluster()
    data = []
    headers = ['Namespace', 'Service Account', 'Role Type', 'Role Name']
    data.append(headers)
    roles = k8s.get_roles_for_service_account(namespace, service_account_name)
    for role in roles:        
        role_list = [namespace, service_account_name, role['type'], role['name']]
        data.append(role_list)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_role_permissions(csv, json, tabulated, namespace, role_name):
    file_name = f'permissions_for_{role_name}_role'
    k8s = KubernetesCluster()
    data = []
    headers = ['Namespace', 'Role Name', 'Resources', 'Verbs']
    role_data = []
    data.append(headers)
    permissions = k8s.get_role_permissions(namespace, role_name)
    for i in permissions:
        role_data = [namespace, role_name, i['resources'], i['verbs']]
        data.append(role_data)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()
    

def get_cluster_role_permissions(csv, json, tabulated, role_name):
    file_name = f'permissions_for_{role_name}_cluster_role'
    k8s = KubernetesCluster()
    data = []
    headers = ['Role Name', 'Resources', 'Verbs']
    role_data = []
    data.append(headers)
    permissions = k8s.get_cluster_role_permissions(role_name)
    for i in permissions:
        role_data = [role_name, i['resources'], i['verbs']]
        data.append(role_data)

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()

# AWS CLOUD STATUS
def get_iam_users(csv, json, tabulated, session):
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

        reporter = Reporter(data, file_name, csv, json, tabulated)
        reporter.reporter()

def get_access_keys(csv, json, tabulated, session):
    file_name = 'access_keys'
    iam_client = session.client('iam')
    response = iam_client.list_users()
    headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
    data = []
    data.append(headers)
    if 'Users' in response:
        users = response['Users']
        for user in users:
            user_name = user['UserName']
            iam_user = IAMUser(session, user_name)
            for i in iam_user.access_keys:
                formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
                access_key_data = [i['AccessKeyId'], i['Status'], user_name, formatted_dt]
                data.append(access_key_data)
    
    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_user_access_keys(csv, json, tabulated, session, user_name):
    file_name = 'user_access_keys'
    headers = ['Access Key ID', 'Status', 'IAM User', 'Creation Date']
    data = []
    data.append(headers)

    iam_user = IAMUser(session, user_name)
    for i in iam_user.access_keys:
        formatted_dt = i['CreateDate'].strftime("%B %d, %Y %H:%M:%S %p")
        access_key_data = [i['AccessKeyId'], i['Status'], user_name, formatted_dt]
        data.append(access_key_data)
            
    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()

def get_ec2_instances(csv, json, tabulated, session, regions):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_security_groups(csv, json, tabulated, session, instance_id, region):
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
    
    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()

def get_lambda_functions(csv, json, tabulated, session, regions):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_lambda_data(csv, json, tabulated, session, function_name, region):
    file_name = 'lambda_data'
    data = []
    headers = ['Function Name', 'Function Role', 'Env Vars']
    data.append(headers)
    try:
        lambda_function = LambdaFunction(session, function_name, region[0])
        lambda_data = [lambda_function.function_name, lambda_function.role_arn,
                        lambda_function.environment_variables]
        
        data.append(lambda_data)
        reporter = Reporter(data, file_name, csv, json, tabulated)
        reporter.reporter()

    except Exception as e:
        print(e)


def get_buckets(csv, json, tabulated, session):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_public_buckets(csv, json, tabulated, session):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_public_objects(csv, json, tabulated, session, bucket_name):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()
    

def get_all_public_objects(csv, json, tabulated, session):
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
    
    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_eks_clusters(csv, json, tabulated, session, regions):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_eks_public_endpoints(session, cluster_name, region):
    region = region [0]
    eks_cluster = EKSCluster(session, cluster_name, region)
    print(eks_cluster.endpoint)


def get_eks_log_status(session, cluster_name, regions):
    eks_cluster = EKSCluster(session, cluster_name, regions[0])
    print(eks_cluster.log_status)


def get_rds_databases(csv, json, tabulated, session, regions):
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

    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()

def get_rds_log_status(session, db_instance_id, regions):
    rds_instance = RDSInstance(session, db_instance_id, regions[0])
    print(rds_instance.log_status)


def get_rds_security_groups(csv, json, tabulated, session, db_instance_id, regions):
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


    reporter = Reporter(data, file_name, csv, json, tabulated)
    reporter.reporter()


def get_rds_public_access(session, db_instance_id, regions):
    rds_instance = RDSInstance(session, db_instance_id, regions[0])
    if rds_instance.publicly_accessible:
        print(f'Endpoint is PUBLIC')
    else:
        print(f'Endpoint is PRIVATE')


def get_all_aws(csv, json, tabulated, session, regions):
    print(['IAM Users'])
    get_iam_users(csv, json, tabulated, session)

    print(['EC2 Instances'])
    get_ec2_instances(csv, json, tabulated, session, regions)

    print(['Lambda Functions'])
    get_lambda_functions(csv, json, tabulated, session, regions)
    
    print(['Public S3 Buckets'])
    get_public_buckets(csv, json, tabulated, session)

    print(['EKS Clusters'])
    get_eks_clusters(csv, json, tabulated, session, regions)

    print(['RDS Databases'])
    get_rds_databases(csv, json, tabulated, session, regions)

