import argparse
import utils.constants

def dredge_parser():
    parser = argparse.ArgumentParser(description=utils.constants.dredge_description)

    # Add the subcommands
    dredge_parser = parser.add_subparsers(dest="subcommand", help="Subcommands")
    dredge_parser.required = False
    
    dredge_parser = config_cmd(dredge_parser)
    dredge_parser = threat_hunting_cmd(dredge_parser)
    dredge_parser = log_retriever_cmd(dredge_parser)
    dredge_parser = cloud_status_cmd(dredge_parser)
    dredge_parser = incident_response_cmd(dredge_parser)

    return parser


def config_cmd(dredge_parser):
    #CONFIG
    # Add the 'Config' subcommand with its options
    config_cmd = dredge_parser.add_parser(utils.constants.config_cmd, help=utils.constants.config_description)
    config_cmd.add_argument(utils.constants.config_argument, required=True, help=utils.constants.config_file_argument_help)
    
    return dredge_parser


def threat_hunting_cmd(dredge_parser):
    #THREAT HUNTING
    # Add the 'Threat Hunting' subcommand with its options
    th_cmd = dredge_parser.add_parser(utils.constants.th_cmd, help=utils.constants.th_help)
    
    # Create subparsers for different subcommands under 'Threat Hunting'
    subparsers = th_cmd.add_subparsers(dest="th_subcommand", help=utils.constants.th_subparser_help)
    subparsers.required = True

    # Add the 'Virus Total' subcommand with its options
    vt_cmd = subparsers.add_parser(utils.constants.th_vt_subparser, help=utils.constants.th_vt_help)
    vt_cmd.add_argument(utils.constants.th_vt_key_argument, required=True, help=utils.constants.th_vt_key_help)
    vt_cmd.add_argument(utils.constants.th_vt_ip_argument, required=False, help=utils.constants.th_vt_ip_help)
    vt_cmd.add_argument(utils.constants.th_vt_file_argument, required=False, help=utils.constants.th_vt_file_help)
    vt_cmd.add_argument(utils.constants.th_vt_hash_argument, required=False, help=utils.constants.th_vt_hash_help)
    vt_cmd.add_argument(utils.constants.th_vt_domain_argument, required=False, help=utils.constants.th_vt_domain_help)

    # Add the 'IP Retriever' subcommand with its options
    ip_cmd = subparsers.add_parser(utils.constants.th_ip_subparser, help=utils.constants.th_ip_help)
    ip_cmd.add_argument(utils.constants.th_ip_file_argument, required=True, help=utils.constants.th_ip_file_help)

    # Add the 'Whois Analyzer' subcommand with its options
    whois_cmd = subparsers.add_parser(utils.constants.th_whois_subparser, help=utils.constants.th_whois_help)
    whois_cmd.add_argument(utils.constants.th_whois_file_argument, required=False, help=utils.constants.th_whois_file_help)
    whois_cmd.add_argument(utils.constants.th_whois_target_argument, required=False, help=utils.constants.th_whois_target_help)

    # Add the 'Shodan Analyzer' subcommand with its options
    shodan_cmd = subparsers.add_parser(utils.constants.th_shodan_subparser, help=utils.constants.th_shodan_help)
    shodan_cmd.add_argument(utils.constants.th_shodan_file_argument, required=False, help=utils.constants.th_shodan_file_help)
    shodan_cmd.add_argument(utils.constants.th_shodan_ip_argument, required=False, help=utils.constants.th_shodan_ip_help)
    shodan_cmd.add_argument(utils.constants.th_shodan_key_argument, required=True, help=utils.constants.th_shodan_key_help)

    # Add the 'aws' subcommand with its options
    aws_th_cmd = subparsers.add_parser(utils.constants.th_aws_subparser, help=utils.constants.th_aws_help)
    aws_th_cmd.add_argument(utils.constants.aws_profile_argument, required=False, help=utils.constants.aws_profile_help)
    aws_th_cmd.add_argument(utils.constants.aws_region_argument, required=False, help=utils.constants.aws_region_help)
    aws_th_cmd.add_argument(utils.constants.start_date_argument, required=False, help=utils.constants.start_date_help)
    aws_th_cmd.add_argument(utils.constants.end_date_argument, required=False, help=utils.constants.end_date_help)
    aws_th_cmd.add_argument(utils.constants.th_aws_ip_argument, required=False, help=utils.constants.th_aws_ip_help)
    aws_th_cmd.add_argument(utils.constants.th_aws_iam_user_argument, required=False, help=utils.constants.th_aws_iam_user_help)
    aws_th_cmd.add_argument(utils.constants.th_aws_access_key_argument, required=False, help=utils.constants.th_aws_access_key_help)
    aws_th_cmd.add_argument(utils.constants.th_aws_timeline_argument, required=False, action="store_true", help=utils.constants.th_aws_timeline_help)
    aws_th_cmd.add_argument(utils.constants.th_aws_dangerous_api_calls_argument, required=False, action='store_true', help=utils.constants.th_aws_dangerous_api_calls_help)
    aws_th_cmd.add_argument('--csv', required=False, action='store_true', help="Set to get csv report.")

    k8s_th_cmd = subparsers.add_parser(utils.constants.th_k8s_subparser, help=utils.constants.th_k8s_subparser_help)
    k8s_th_cmd.add_argument(utils.constants.k8s_config_argument, required=False, help=utils.constants.k8s_config_help)
    k8s_th_cmd.add_argument(utils.constants.k8s_role_argument, required=False, help=utils.constants.k8s_role_help)
    k8s_th_cmd.add_argument(utils.constants.k8s_namespace_argument, required=False, help=utils.constants.k8s_namespace_help)
    k8s_th_cmd.add_argument(utils.constants.k8s_service_account_argument, required=False, help=utils.constants.k8s_service_account_help)
    k8s_th_cmd.add_argument(utils.constants.th_k8s_dangerous_permissions_argument, action="store_true", required=False, help=utils.constants.th_k8s_dangerous_permissions_help)
    k8s_th_cmd.add_argument(utils.constants.k8s_no_kubesystem_argument, action="store_true", required=False, help=utils.constants.k8s_no_kubesystem_help)
    k8s_th_cmd.add_argument('--csv', required=False, action='store_true', help="Set to get csv report.")

    return dredge_parser


def log_retriever_cmd(dredge_parser):
    #LOG RETRIEVER 
    # Add the 'Log Retriever' subcommand with its options
    lr_cmd = dredge_parser.add_parser(utils.constants.lr_cmd, help=utils.constants.lr_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = lr_cmd.add_subparsers(dest="lr_subcommand", help=utils.constants.lr_subparser_help)
    subparsers.required = True  

    # Add the 'gcp' subcommand with its options
    gcp_lr_cmd = subparsers.add_parser(utils.constants.lr_gcp_subparser, help = utils.constants.lr_gcp_subparser_help)
    gcp_lr_cmd.add_argument(utils.constants.lr_gcp_cred_file_argument, required=False, help=utils.constants.lr_gcp_cred_file_help)
    gcp_lr_cmd.add_argument(utils.constants.start_date_argument, required=False, help=utils.constants.start_date_help)
    gcp_lr_cmd.add_argument(utils.constants.end_date_argument, required=False, help=utils.constants.end_date_help)


    # Add the 'k8s' subcommand with its options
    k8s_lr_cmd = subparsers.add_parser(utils.constants.lr_k8s_subparser, help=utils.constants.lr_k8s_subparser_help)
    k8s_lr_cmd.add_argument(utils.constants.k8s_config_argument, required=False, help=utils.constants.k8s_config_help)
    k8s_lr_cmd.add_argument(utils.constants.start_date_argument, required=False, help=utils.constants.start_date_help)
    k8s_lr_cmd.add_argument(utils.constants.end_date_argument, required=False, help=utils.constants.end_date_help)
    k8s_lr_cmd.add_argument(utils.constants.k8s_pod_argument, required=False, help=utils.constants.k8s_pod_help)
    k8s_lr_cmd.add_argument(utils.constants.k8s_namespace_argument, required=False, help=utils.constants.k8s_namespace_help)
    k8s_lr_cmd.add_argument(utils.constants.lr_k8s_events_argument, required=False, action="store_true", help=utils.constants.lr_k8s_events_help)
 

    # Add the 'aws' subcommand with its options
    aws_lr_cmd = subparsers.add_parser(utils.constants.lr_aws_subparser, help=utils.constants.lr_aws_subparser_help)
    aws_lr_cmd.add_argument(utils.constants.aws_profile_argument, required=False, help=utils.constants.aws_profile_help)
    aws_lr_cmd.add_argument(utils.constants.aws_region_argument, required=False, help=utils.constants.aws_region_help)
    aws_lr_cmd.add_argument(utils.constants.start_date_argument, required=False, help=utils.constants.start_date_help)
    aws_lr_cmd.add_argument(utils.constants.end_date_argument, required=False, help=utils.constants.end_date_help)
    aws_lr_cmd.add_argument(utils.constants.lr_aws_log_argument, choices=utils.constants.lr_aws_log_choices, 
                         required=True, help=utils.constants.lr_aws_log_help)
    aws_lr_cmd.add_argument(utils.constants.lr_aws_target_argument, required=False, help=utils.constants.lr_aws_target_help)

    # Add the 'github' subcommand with its options
    github_lr_cmd = subparsers.add_parser(utils.constants.lr_github_subparser, help=utils.constants.lr_github_subparser_help)
    github_lr_cmd.add_argument(utils.constants.github_org_argument, required=False, help=utils.constants.github_org_help)
    github_lr_cmd.add_argument(utils.constants.github_ent_argument, required=False, help=utils.constants.github_ent_help)
    github_lr_cmd.add_argument(utils.constants.github_token_argument, required=True, help=utils.constants.github_token_help)
    github_lr_cmd.add_argument(utils.constants.start_date_argument, required=False, help=utils.constants.start_date_help)
    github_lr_cmd.add_argument(utils.constants.end_date_argument, required=False, help=utils.constants.end_date_help)

    return dredge_parser


def cloud_status_cmd(dredge_parser):
    #CLOUD STATUS
    # Add the 'Cloud Status' subcommand with its options
    cs_cmd = dredge_parser.add_parser(utils.constants.cs_cmd, help=utils.constants.cs_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = cs_cmd.add_subparsers(dest="cs_subcommand", help=utils.constants.cs_subparser_help)
    subparsers.required = True  

    # Add the 'aws' subcommand with its options
    aws_cs_cmd = subparsers.add_parser(utils.constants.cs_aws_subparser, help=utils.constants.cs_aws_subparser_help)
    aws_cs_cmd.add_argument(utils.constants.aws_profile_argument, required=False, help=utils.constants.aws_profile_help)
    aws_cs_cmd.add_argument(utils.constants.aws_region_argument, required=False, help=utils.constants.aws_region_help)
   
    # CS AWS GET SUBPARSER COMMANDS
    ### ADD GET IAM USER | GET POLICIES FROM USER | GET EC2 INSTANCE | GET LAMBDA y asi
    ## IAM
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_iam_users_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_iam_users_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_access_key_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_access_key_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_user_access_key_argument, help=utils.constants.ir_aws_get_user_access_key_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_iam_user_argument, help=utils.constants.ir_aws_get_iam_user_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_iam_role_argument, help=utils.constants.ir_aws_get_iam_role_help)
    aws_cs_cmd.add_argument('--csv', required=False, action='store_true', help="Set to get csv report.")

    ## EC2
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_ec2_instances_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_ec2_instances_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_ec2_instances_all_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_ec2_instances_all_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_ec2_instance_profile_argument, required=False, help=utils.constants.ir_aws_get_ec2_instance_profile_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_ec2_security_groups_argument, required=False, help=utils.constants.ir_aws_get_ec2_security_groups_help)
    
    ## LAMBDA
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_lambda_functions_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_lambda_functions_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_lambda_data_argument, required=False, help=utils.constants.ir_aws_get_lambda_data_help)
    
    ## BUCKETS
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_buckets_argument, action='store_true', required=False, help=utils.constants.ir_aws_get_buckets_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_public_buckets_argument, action='store_true', required=False, help=utils.constants.ir_aws_get_public_buckets_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_public_objects_argument, required=False, help=utils.constants.ir_aws_get_public_objects_help)
    
    #EKS
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_eks_clusters_argument, action='store_true', required=False, help=utils.constants.ir_aws_get_eks_clusters_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_eks_public_endpoints_argument, required=False, help=utils.constants.ir_aws_get_eks_public_endpoints_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_eks_log_status_argument, required=False, help=utils.constants.ir_aws_get_eks_log_status_help)
    
    ## RDS
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_rds_databases_argument, action='store_true', required=False, help=utils.constants.ir_aws_get_rds_databases_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_rds_log_status_argument, required=False, help=utils.constants.ir_aws_get_rds_log_status_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_rds_security_groups_argument, required=False, help=utils.constants.ir_aws_get_rds_security_groups_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_rds_public_access_argument, required=False, help=utils.constants.ir_aws_get_rds_public_access_help)
    aws_cs_cmd.add_argument(utils.constants.ir_aws_get_aws_all_argument, required=False, action='store_true', help=utils.constants.ir_aws_get_aws_all_help)

    # Add the 'k8s' subcommand with its options
    k8s_cs_cmd = subparsers.add_parser(utils.constants.cs_k8s_subparser, help=utils.constants.cs_k8s_subparser_help)
    k8s_cs_cmd.add_argument(utils.constants.k8s_config_argument, required=False, help=utils.constants.k8s_config_help)
    k8s_cs_cmd.add_argument(utils.constants.k8s_pod_argument, required=False, help=utils.constants.k8s_pod_help)
    k8s_cs_cmd.add_argument(utils.constants.k8s_namespace_argument, required=False, help=utils.constants.k8s_namespace_help)
    k8s_cs_cmd.add_argument(utils.constants.k8s_service_account_argument, required=False, help=utils.constants.k8s_service_account_help)

    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_namespaces_argument, action="store_true", required=False, help=utils.constants.cs_k8s_get_namespaces_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_pods_argument, action="store_true", required=False, help=utils.constants.cs_k8s_get_pods_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_secrets_argument, action="store_true", required=False, help=utils.constants.cs_k8s_get_secrets_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_service_accounts_argument, action="store_true", required=False, help=utils.constants.cs_k8s_get_service_accounts_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_roles_argument, action="store_true", required=False, help=utils.constants.cs_k8s_get_roles_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_get_role_permissions_argument, required=False, help=utils.constants.cs_k8s_get_role_permissions_help)
    k8s_cs_cmd.add_argument(utils.constants.cs_k8s_whit_permissions_argument, action="store_true", required=False, help=utils.constants.cs_k8s_whit_permissions_help)
    k8s_cs_cmd.add_argument('--csv', required=False, action='store_true', help="Set to get csv report.")

    return dredge_parser

def incident_response_cmd(dredge_parser):
    #INCIDENT RESPONSE
    # Add the 'Incident Response' subcommand with its options
    ir_cmd = dredge_parser.add_parser(utils.constants.ir_cmd, help=utils.constants.ir_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = ir_cmd.add_subparsers(dest="ir_subcommand", help=utils.constants.ir_subparser_help)
    subparsers.required = True  

    # Add the 'aws' subcommand with its options
    aws_ir_cmd = subparsers.add_parser(utils.constants.ir_aws_subparser, help=utils.constants.ir_aws_subparser_help)
    aws_ir_cmd.add_argument(utils.constants.aws_profile_argument, required=False, help=utils.constants.aws_profile_help)
    aws_ir_cmd.add_argument(utils.constants.aws_region_argument, required=False, help=utils.constants.aws_region_help)
  
    # Create subparsers for different subcommands under 'AWS Incident Response'
    ir_subparsers = aws_ir_cmd.add_subparsers(dest="aws_ir_subcommand", help=utils.constants.aws_ir_subparser_help)
    ir_subparsers.required = True  
    
    # IR DISABLE SUBPARSER COMMANDS
    aws_disable_ir_cmd = ir_subparsers.add_parser(utils.constants.ir_aws_disable_subparser, help=utils.constants.ir_aws_disable_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_access_key_argument, required=False, help=utils.constants.ir_aws_disable_access_key_help)
    aws_disable_ir_cmd.add_argument(utils.constants.aws_iam_user, required=False, help=utils.constants.aws_iam_user_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_user_access_key_argument, required=False, help=utils.constants.ir_aws_disable_aws_user_access_key_help)    
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_user_console_login_argument, action='store_true', required=False, help=utils.constants.ir_aws_disable_aws_user_console_login_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_s3_public_argument, required=False, help=utils.constants.ir_aws_disable_aws_s3_public_help)
    aws_disable_ir_cmd.add_argument(utils.constants.aws_bucket, required=False, help=utils.constants.aws_bucket_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_object_public_argument, required=False, help=utils.constants.ir_aws_disable_aws_object_public_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_eks_public_argument, required=False, help=utils.constants.ir_aws_disable_aws_eks_public_help)
    aws_disable_ir_cmd.add_argument(utils.constants.ir_aws_disable_aws_rds_public_argument, required=False, help=utils.constants.ir_aws_disable_aws_rds_public_help)

    # IR DELETE SUBPARSER COMMANDS
    ## REMOVE ACCESS KEYS (?)
    aws_delete_ir_cmd = ir_subparsers.add_parser(utils.constants.ir_aws_delete_subparser, help=utils.constants.ir_aws_delete_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_iam_user_argument, required=False, help=utils.constants.ir_aws_delete_iam_user_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_iam_group_argument, required=False, help=utils.constants.ir_aws_delete_iam_group_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_iam_group_policies_argument, required=False, help=utils.constants.ir_aws_delete_iam_group_policies_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_iam_role_argument, required=False, help=utils.constants.ir_aws_delete_iam_role_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_instance_profile_argument, required=False, help=utils.constants.ir_aws_delete_instance_profile_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_lambda_role_argument, required=False, help=utils.constants.ir_aws_delete_lambda_role_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_lambda_argument, required=False, help=utils.constants.ir_aws_delete_lambda_help)
    aws_delete_ir_cmd.add_argument(utils.constants.ir_aws_delete_ec2_instance_argument, required=False, help=utils.constants.ir_aws_delete_ec2_instance_help)

    # IR RESPOND SUBPARSER COMMANDS
    aws_respond_ir_cmd = ir_subparsers.add_parser(utils.constants.ir_aws_respond_subparser, help=utils.constants.ir_aws_respond_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_acquire_volume_image_argument, action='store_true', required=False, help=utils.constants.ir_aws_respond_acquire_volume_image_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_enable_ec2_termination_protection_argument, action='store_true', required=False, help=utils.constants.ir_aws_respond_enable_ec2_termination_protection_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_tag_ec2_forensics_argument, required=False, help=utils.constants.ir_aws_respond_tag_ec2_forensics_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_isolate_ec2_instance_argument, required=False, help=utils.constants.ir_aws_respond_isolate_ec2_instance_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_enable_eks_logs_argument, required=False, help=utils.constants.ir_aws_respond_enable_eks_logs_help)
    aws_respond_ir_cmd.add_argument(utils.constants.ir_aws_respond_enable_rds_deletion_protection_argument, required=False, help=utils.constants.ir_aws_respond_enable_rds_deletion_protection_help)
    aws_respond_ir_cmd.add_argument(utils.constants.aws_instance_id, required=False, help=utils.constants.aws_instance_id_help)

    return dredge_parser