import argparse
import engine.constants

def dredge_parser():
    parser = argparse.ArgumentParser(description=engine.constants.dredge_description)
    parser.add_argument('--csv', required=False, action='store_true', help="Set to get csv report instad of tabulation.")

    # Add the subcommands
    dredge_parser = parser.add_subparsers(dest="subcommand", help="Subcommands")
    dredge_parser.required = False

    #CONFIG
    # Add the 'Config' subcommand with its options
    config_cmd = dredge_parser.add_parser(engine.constants.config_cmd, help=engine.constants.config_description)
    config_cmd.add_argument(engine.constants.config_argument, required=True, help=engine.constants.config_file_argument_help)
    
    #THREAT HUNTING
    # Add the 'Threat Hunting' subcommand with its options
    th_cmd = dredge_parser.add_parser(engine.constants.th_cmd, help=engine.constants.th_help)
    
    # Create subparsers for different subcommands under 'Threat Hunting'
    subparsers = th_cmd.add_subparsers(dest="th_subcommand", help=engine.constants.th_subparser_help)
    subparsers.required = True

    # Add the 'Virus Total' subcommand with its options
    vt_cmd = subparsers.add_parser(engine.constants.th_vt_subparser, help=engine.constants.th_vt_help)
    vt_cmd.add_argument(engine.constants.th_vt_key_argument, required=True, help=engine.constants.th_vt_key_help)
    vt_cmd.add_argument(engine.constants.th_vt_ip_argument, required=False, help=engine.constants.th_vt_ip_help)
    vt_cmd.add_argument(engine.constants.th_vt_file_argument, required=False, help=engine.constants.th_vt_file_help)
    vt_cmd.add_argument(engine.constants.th_vt_hash_argument, required=False, help=engine.constants.th_vt_hash_help)
    vt_cmd.add_argument(engine.constants.th_vt_domain_argument, required=False, help=engine.constants.th_vt_domain_help)

    # Add the 'IP Retriever' subcommand with its options
    ip_cmd = subparsers.add_parser(engine.constants.th_ip_subparser, help=engine.constants.th_ip_help)
    ip_cmd.add_argument(engine.constants.th_ip_file_argument, required=True, help=engine.constants.th_ip_file_help)

    # Add the 'aws' subcommand with its options
    aws_th_cmd = subparsers.add_parser(engine.constants.th_aws_subparser, help=engine.constants.th_aws_help)
    aws_th_cmd.add_argument(engine.constants.aws_profile_argument, required=False, help=engine.constants.aws_profile_help)
    aws_th_cmd.add_argument(engine.constants.aws_region_argument, required=False, help=engine.constants.aws_region_help)
    aws_th_cmd.add_argument(engine.constants.start_date_argument, required=False, help=engine.constants.start_date_help)
    aws_th_cmd.add_argument(engine.constants.end_date_argument, required=False, help=engine.constants.end_date_help)
#    aws_th_cmd.add_argument("--ips", required=False, help="Search for api calls from those ips")

    #LOG RETRIEVER 
    # Add the 'Log Retriever' subcommand with its options
    lr_cmd = dredge_parser.add_parser(engine.constants.lr_cmd, help=engine.constants.lr_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = lr_cmd.add_subparsers(dest="lr_subcommand", help=engine.constants.lr_subparser_help)
    subparsers.required = True  

    # Add the 'aws' subcommand with its options
    aws_lr_cmd = subparsers.add_parser(engine.constants.lr_aws_subparser, help=engine.constants.lr_aws_subparser_help)
    aws_lr_cmd.add_argument(engine.constants.aws_profile_argument, required=False, help=engine.constants.aws_profile_help)
    aws_lr_cmd.add_argument(engine.constants.aws_region_argument, required=False, help=engine.constants.aws_region_help)
    aws_lr_cmd.add_argument(engine.constants.start_date_argument, required=False, help=engine.constants.start_date_help)
    aws_lr_cmd.add_argument(engine.constants.end_date_argument, required=False, help=engine.constants.end_date_help)
    aws_lr_cmd.add_argument(engine.constants.lr_aws_log_argument, choices=engine.constants.lr_aws_log_choices, 
                         required=True, help=engine.constants.lr_aws_log_help)
    aws_lr_cmd.add_argument(engine.constants.lr_aws_target_argument, required=False, help=engine.constants.lr_aws_target_help)

    # Add the 'github' subcommand with its options
    github_lr_cmd = subparsers.add_parser(engine.constants.lr_github_subparser, help=engine.constants.lr_github_subparser_help)
    github_lr_cmd.add_argument(engine.constants.github_org_argument, required=False, help=engine.constants.github_org_help)
    github_lr_cmd.add_argument(engine.constants.github_ent_argument, required=False, help=engine.constants.github_ent_help)
    github_lr_cmd.add_argument(engine.constants.github_token_argument, required=True, help=engine.constants.github_token_help)
    github_lr_cmd.add_argument(engine.constants.start_date_argument, required=False, help=engine.constants.start_date_help)
    github_lr_cmd.add_argument(engine.constants.end_date_argument, required=False, help=engine.constants.end_date_help)

    #CLOUD STATUS
    # Add the 'Cloud Status' subcommand with its options
    cs_cmd = dredge_parser.add_parser(engine.constants.cs_cmd, help=engine.constants.cs_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = cs_cmd.add_subparsers(dest="cs_subcommand", help=engine.constants.cs_subparser_help)
    subparsers.required = True  

    # Add the 'aws' subcommand with its options
    aws_cs_cmd = subparsers.add_parser(engine.constants.cs_aws_subparser, help=engine.constants.cs_aws_subparser_help)
    aws_cs_cmd.add_argument(engine.constants.aws_profile_argument, required=False, help=engine.constants.aws_profile_help)
    aws_cs_cmd.add_argument(engine.constants.aws_region_argument, required=False, help=engine.constants.aws_region_help)
   
    # CS AWS GET SUBPARSER COMMANDS
    ### ADD GET IAM USER | GET POLICIES FROM USER | GET EC2 INSTANCE | GET LAMBDA y asi
    ## IAM
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_iam_users_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_iam_users_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_access_key_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_access_key_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_user_access_key_argument, help=engine.constants.ir_aws_get_user_access_key_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_iam_user_argument, help=engine.constants.ir_aws_get_iam_user_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_iam_role_argument, help=engine.constants.ir_aws_get_iam_role_help)

    ## EC2
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_ec2_instances_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_ec2_instances_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_ec2_instances_all_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_ec2_instances_all_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_ec2_instance_profile_argument, required=False, help=engine.constants.ir_aws_get_ec2_instance_profile_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_ec2_security_groups_argument, required=False, help=engine.constants.ir_aws_get_ec2_security_groups_help)
    
    ## LAMBDA
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_lambda_functions_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_lambda_functions_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_lambda_data_argument, required=False, help=engine.constants.ir_aws_get_lambda_data_help)
    
    ## BUCKETS
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_buckets_argument, action='store_true', required=False, help=engine.constants.ir_aws_get_buckets_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_public_buckets_argument, action='store_true', required=False, help=engine.constants.ir_aws_get_public_buckets_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_public_objects_argument, required=False, help=engine.constants.ir_aws_get_public_objects_help)
    
    #EKS
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_eks_clusters_argument, action='store_true', required=False, help=engine.constants.ir_aws_get_eks_clusters_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_eks_public_endpoints_argument, required=False, help=engine.constants.ir_aws_get_eks_public_endpoints_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_eks_log_status_argument, required=False, help=engine.constants.ir_aws_get_eks_log_status_help)
    
    ## RDS
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_rds_databases_argument, action='store_true', required=False, help=engine.constants.ir_aws_get_rds_databases_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_rds_log_status_argument, required=False, help=engine.constants.ir_aws_get_rds_log_status_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_rds_security_groups_argument, required=False, help=engine.constants.ir_aws_get_rds_security_groups_help)
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_rds_public_access_argument, required=False, help=engine.constants.ir_aws_get_rds_public_access_help)
    
    aws_cs_cmd.add_argument(engine.constants.ir_aws_get_aws_all_argument, required=False, action='store_true', help=engine.constants.ir_aws_get_aws_all_help)



    #INCIDENT RESPONSE
    # Add the 'Incident Response' subcommand with its options
    ir_cmd = dredge_parser.add_parser(engine.constants.ir_cmd, help=engine.constants.ir_help)

    # Create subparsers for different subcommands under 'Log Retriever'
    subparsers = ir_cmd.add_subparsers(dest="ir_subcommand", help=engine.constants.ir_subparser_help)
    subparsers.required = True  

    # Add the 'aws' subcommand with its options
    aws_ir_cmd = subparsers.add_parser(engine.constants.ir_aws_subparser, help=engine.constants.ir_aws_subparser_help)
    aws_ir_cmd.add_argument(engine.constants.aws_profile_argument, required=False, help=engine.constants.aws_profile_help)
    aws_ir_cmd.add_argument(engine.constants.aws_region_argument, required=False, help=engine.constants.aws_region_help)
  
    # Create subparsers for different subcommands under 'AWS Incident Response'
    ir_subparsers = aws_ir_cmd.add_subparsers(dest="aws_ir_subcommand", help=engine.constants.aws_ir_subparser_help)
    ir_subparsers.required = True  
    
    # IR DISABLE SUBPARSER COMMANDS
    aws_disable_ir_cmd = ir_subparsers.add_parser(engine.constants.ir_aws_disable_subparser, help=engine.constants.ir_aws_disable_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_access_key_argument, required=False, help=engine.constants.ir_aws_disable_access_key_help)
    aws_disable_ir_cmd.add_argument(engine.constants.aws_iam_user, required=False, help=engine.constants.aws_iam_user_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_user_access_key_argument, required=False, help=engine.constants.ir_aws_disable_aws_user_access_key_help)    
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_user_console_login_argument, action='store_true', required=False, help=engine.constants.ir_aws_disable_aws_user_console_login_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_s3_public_argument, required=False, help=engine.constants.ir_aws_disable_aws_s3_public_help)
    aws_disable_ir_cmd.add_argument(engine.constants.aws_bucket, required=False, help=engine.constants.aws_bucket_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_object_public_argument, required=False, help=engine.constants.ir_aws_disable_aws_object_public_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_eks_public_argument, required=False, help=engine.constants.ir_aws_disable_aws_eks_public_help)
    aws_disable_ir_cmd.add_argument(engine.constants.ir_aws_disable_aws_rds_public_argument, required=False, help=engine.constants.ir_aws_disable_aws_rds_public_help)

    # IR DELETE SUBPARSER COMMANDS
    ## REMOVE ACCESS KEYS (?)
    aws_delete_ir_cmd = ir_subparsers.add_parser(engine.constants.ir_aws_delete_subparser, help=engine.constants.ir_aws_delete_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_iam_user_argument, required=False, help=engine.constants.ir_aws_delete_iam_user_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_iam_group_argument, required=False, help=engine.constants.ir_aws_delete_iam_group_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_iam_group_policies_argument, required=False, help=engine.constants.ir_aws_delete_iam_group_policies_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_iam_role_argument, required=False, help=engine.constants.ir_aws_delete_iam_role_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_instance_profile_argument, required=False, help=engine.constants.ir_aws_delete_instance_profile_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_lambda_role_argument, required=False, help=engine.constants.ir_aws_delete_lambda_role_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_lambda_argument, required=False, help=engine.constants.ir_aws_delete_lambda_help)
    aws_delete_ir_cmd.add_argument(engine.constants.ir_aws_delete_ec2_instance_argument, required=False, help=engine.constants.ir_aws_delete_ec2_instance_help)

    # IR RESPOND SUBPARSER COMMANDS
    aws_respond_ir_cmd = ir_subparsers.add_parser(engine.constants.ir_aws_respond_subparser, help=engine.constants.ir_aws_respond_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_acquire_volume_image_argument, action='store_true', required=False, help=engine.constants.ir_aws_respond_acquire_volume_image_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_enable_ec2_termination_protection_argument, action='store_true', required=False, help=engine.constants.ir_aws_respond_enable_ec2_termination_protection_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_tag_ec2_forensics_argument, required=False, help=engine.constants.ir_aws_respond_tag_ec2_forensics_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_isolate_ec2_instance_argument, required=False, help=engine.constants.ir_aws_respond_isolate_ec2_instance_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_enable_eks_logs_argument, required=False, help=engine.constants.ir_aws_respond_enable_eks_logs_help)
    aws_respond_ir_cmd.add_argument(engine.constants.ir_aws_respond_enable_rds_deletion_protection_argument, required=False, help=engine.constants.ir_aws_respond_enable_rds_deletion_protection_help)
    aws_respond_ir_cmd.add_argument(engine.constants.aws_instance_id, required=False, help=engine.constants.aws_instance_id_help)

    return parser

