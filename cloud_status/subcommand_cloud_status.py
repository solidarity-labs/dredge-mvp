from cloud_status.engine_cloud_status import get_iam_users, get_access_keys, get_user_access_keys, get_ec2_instances, get_security_groups, get_eks_clusters, get_iam_users
from cloud_status.engine_cloud_status import  get_lambda_functions, get_lambda_data, get_buckets, get_public_buckets, get_public_objects, get_all_public_objects, get_all_aws
from cloud_status.engine_cloud_status import  get_eks_public_endpoints, get_eks_log_status, get_rds_databases, get_rds_log_status, get_rds_security_groups, get_rds_public_access
from cloud_status.engine_cloud_status import get_namespaces, get_pods, get_secrets, get_all_services_accounts, get_roles_for_service_account
from cloud_status.engine_cloud_status import get_role_permissions,get_cluster_role_permissions, get_all_services_accounts_with_permissions
from utils.utils import aws_session_validator, get_enabled_regions
from modules.class_aws_ec2_instance import EC2Instance
import utils.constants



def cloud_status_subcommand(args):
    ## Check reporting flag CSV or Tabulated
    args.tabulated = True
    args.json = False

    if args.cs_subcommand == utils.constants.cs_aws_subparser:
        ## GET AWS SUBPARSER
        session = aws_session_validator(args)
        if args.all:
            regions = get_enabled_regions(session)
        else:
            regions = [args.region]

        ### GET AWS IAM DATA
        if args.iam_users == True:
            get_iam_users(args.csv, args.json, args.tabulated, session)

        elif args.get_user:
            pass
            #get_user_data(session, args.get_user)

        if args.access_keys:
            get_access_keys(args.csv, args.json, args.tabulated, session)
            
        if args.user_access_keys:
            get_user_access_keys(args.csv, args.json, args.tabulated, session, args.user_access_keys)

        # GET AWS EC2 DATA
        if args.ec2_instances:
            get_ec2_instances(args.csv, args.json, args.tabulated, session, regions)

        if args.ec2_instance_profile:
            instance_id = args.ec2_instance_profile
            ec2_instance = EC2Instance(session, instance_id, args.region)
            ec2_instance.acquire_EC2_instance_profile(session)
        
        if args.security_groups:
            instance_id = args.security_groups
            region = args.region
            get_security_groups(args.csv, args.json, args.tabulated, session, instance_id, region)
        
        # GET AWS LAMBDA DATA
        if args.lambda_functions:
            get_lambda_functions(args.csv, args.json, args.tabulated, session, regions)
        
        if args.lambda_data:
            get_lambda_data(args.csv, args.json, args.tabulated, session, args.lambda_data, regions)

        # GET AWS S3 BUCKET DATA
        if args.buckets:
            get_buckets(args.csv, args.json, args.tabulated, session)

        if args.public_buckets:
            get_public_buckets(args.csv, args.json, args.tabulated, session)
        
        if args.public_objects:
            if args.public_objects == "all":
                get_all_public_objects(args.csv, args.json, args.tabulated, session)
            else:
                get_public_objects(args.csv, args.json, args.tabulated, session, args.public_objects)

        # GET AWS EKS DATA
        if args.eks_clusters:
            get_eks_clusters(args.csv, args.json, args.tabulated, session, regions)

        if args.eks_public_endpoints:
            get_eks_public_endpoints(session, args.eks_public_endpoints, regions)
        
        if args.eks_log_status:
            get_eks_log_status(session, args.eks_log_status, regions)

        # GET AWS RDS DATA
        if args.rds_databases:
            get_rds_databases(args.csv, args.json, args.tabulated, session, regions)
        
        if args.rds_log_status:
            get_rds_log_status(session, args.rds_log_status, regions)
        
        if args.rds_security_groups:
            get_rds_security_groups(args.csv, args.json, args.tabulated, session, args.rds_security_groups, regions)
        
        if args.rds_public_access:
            get_rds_public_access(session, args.rds_public_access, regions)

        if args.aws_all:
            regions = get_enabled_regions(session)
            get_all_aws(args.csv, args.json, args.tabulated, session, regions)

    elif args.cs_subcommand == utils.constants.cs_k8s_subparser:
        if args.get_namespaces:
            get_namespaces()

        elif args.get_pods:
            if not args.namespace:
                args.namespace = "*"

            get_pods(args.csv, args.json, args.tabulated, args.namespace)

        elif args.get_secrets:
            if not args.namespace:
                args.namespace = "*"

            get_secrets(args.csv, args.json, args.tabulated, args.namespace)

        elif args.get_service_accounts:
            if not args.namespace:
                args.namespace = '*'
        
            if args.with_permissions:
                get_all_services_accounts_with_permissions(args.csv, args.json, args.tabulated, args.namespace)
            else:
                get_all_services_accounts(args.csv, args.json, args.tabulated, args.namespace)



        elif args.get_roles:
            get_roles_for_service_account(args.csv, args.json, args.tabulated, args.namespace, args.service_account)    
            
        elif args.get_role_permissions:
            if args.namespace:
                get_role_permissions(args.csv, args.json, args.tabulated, args.namespace, args.get_role_permissions)
            
            else:
                get_cluster_role_permissions(args.csv, args.json, args.tabulated, args.get_role_permissions)

