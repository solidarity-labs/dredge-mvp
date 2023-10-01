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

def disable_aws_access_key(session, iam_user_name, access_key_id):
    try:
        user = IAMUser(session, iam_user_name)
        user.disable_access_key(access_key_id, iam_user_name, session)
    except Exception as e:
        print(e)


def disable_all_user_access_keys(session, iam_user_name):
    try:
        user = IAMUser(session, iam_user_name)
        user.disable_all_access_key(session)
    except Exception as e:
        print(e)


def disable_user_console_login(session, iam_user_name):
    try:
        user = IAMUser(session, iam_user_name)
        user.remove_login_profile(session)
    except Exception as e:
        print(e)


def disable_s3_public_access(session, bucket_name):
    try:
        s3_bucket = S3Bucket(session, bucket_name)
        s3_bucket.block_s3_bucket_public_access(s3_bucket.bucket_name, session)
    except Exception as e:
        print(e)


def disable_object_public_access(session, bucket_name, object_name):
    try:
        s3_bucket = S3Bucket(session, bucket_name)
        s3_bucket.block_s3_object_public_access(s3_bucket.bucket_name, object_name, session)
    except Exception as e:
        print(e)


def disable_eks_public_access(session, cluster_name, region):
    eks_cluster = EKSCluster(session, cluster_name, region)
    eks_cluster.block_eks_public_endpoint(session)


def disable_rds_public_access(session, db_instance_id, region):
    rds_instance = RDSInstance(session, db_instance_id, region)
    rds_instance.block_RDS_public_access(rds_instance.db_instance_identifier, session)


def delete_iam_user(session, iam_user_name):
    try:
        user = IAMUser(session, iam_user_name).delete_IAM_user(iam_user_name, session)

    except Exception as e:
        print(e)


def delete_iam_group(session, iam_group_name):
    try:
        group = IAMGroup(session, iam_group_name)
        group.delete_IAM_group(session)
    except Exception as e:
        print(e)


def detach_group_policies(session, iam_group_name):
    try:
        group = IAMGroup(session, iam_group_name)
        group.detach_policies_from_group(session)
    except Exception as e:
        print(e)


def delete_iam_role(session, iam_role_name):
    try:
        role = IAMRole(session, iam_role_name)
        role.delete_IAM_role(session)
    except Exception as e:
        print(e)


def delete_instance_profile(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.acquire_EC2_instance_profile(session)
    ec2_instance.removeInstanceProfile(session)


def delete_ec2_instance(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.terminate_ec2_instance(session)


def delete_lambda_role(session, function_name, region):
    try:
        lambda_function = LambdaFunction(session, function_name, region)
        lambda_function.remove_lambda_roles(lambda_function.function_name, session)
    except Exception as e:
        print(e)


def delete_lambda_function(session, function_name, region):
    try:
        lambda_function = LambdaFunction(session, function_name, region)
        lambda_function.delete_lambda(lambda_function.function_name, session)
    except Exception as e:
        print(e)


def acquire_volume_image(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.acquire_ec2_volume_images(session)


def enable_ec2_termination_protection(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.enable_ec2_termination_protection(session)


def tag_ec2_forensics(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.tag_ec2_instance(session)


def isolate_ec2_instance(session, instance_id, region):
    ec2_instance = EC2Instance(session, instance_id, region)
    ec2_instance.isolate_ec2_instance(session)


def enable_eks_logs(session, cluster_name, region):
    eks_cluster = EKSCluster(session, cluster_name, region)
    eks_cluster.enable_eks_logs(session)


def enable_rds_deletion_protection(session, db_instance_id, region):
    rds_instance = RDSInstance(session, db_instance_id, region)
    rds_instance.block_RDS_public_access(rds_instance.db_instance_identifier, session)