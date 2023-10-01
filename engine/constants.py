# CLI TEXT
## DREDGE
dredge_description = "Dredge Threat Hunting"
default_profile = 'default'
default_region = 'us-east-1'

## CONFIG 
config_cmd = "co"
config_description = "Chose a config file"
config_argument = "--file"
config_file_argument_help = "Target a Config File  - config.yaml in the root directory"

## THREAT HUNTING
th_cmd = "th"
th_help = "Threat Hunting subcommands - You can get IPs, analyze with VirusTotal and much more!"
th_subparser_help = "Threat Hunting subcommands - You can get IPs, analyze with VirusTotal and much more!"

### TH VirusTotal Subparser
th_vt_subparser = "vt"
th_vt_help = "VirusTotal Hunting - Analyze ips from a file | target one IP, hash or domain"

th_vt_key_argument = "--key"
th_vt_key_help = "VirusTotal API Key"

th_vt_ip_argument = "--ip"
th_vt_ip_help = "VirusTotal Hunting for IPs"

th_vt_file_argument = "--file"
th_vt_file_help = "VirusTotal Hunting for IPs from a file"

th_vt_hash_argument = "--hash"
th_vt_hash_help = "VirusTotal Hunting for Hash"

th_vt_domain_argument = "--domain"
th_vt_domain_help = "VirusTotal Hunting for domains"

## TH IP RETRIEVER
th_ip_subparser = "ip"
th_ip_help = "Get a list of IPs from file"

th_ip_file_argument = "--file"
th_ip_file_help = "Get a list of IPs from file"

## TH AWS 
th_aws_subparser = "aws"
th_aws_help = "Hunt in AWS Event History for dangerous API Calls"

# LOG RETRIEVER
lr_cmd = "lr"
lr_help = "Log Retriever Subcommands - Get logs from different sources like AWS and Github"
lr_subparser_help = "Log Retriever Subcommands - Get logs from different sources like AWS and Github"

### LR AWS Subparser
lr_aws_subparser = "aws"
lr_aws_subparser_help ="AWS Subparser for Log Retriever"

lr_aws_log_argument = "--log"
lr_aws_log_choices = ['s3', 'guardduty', 'event_history', 'cloudwatch']
lr_aws_log_help = "Choose what log to retrieve data from - S3 | Guardduty | EventHistory | Cloudwatch"

lr_aws_target_argument = "--target"
lr_aws_target_help = "Bucket Name or Cloudwatch Log Group"

### LR GITHUB
lr_github_subparser = "github"
lr_github_subparser_help ="Get Github logs"

# CLOUD STATUS
## CS SUBPARSER
cs_cmd = "cs"
cs_help = "Cloud Status Subcommands - Get tactical data from the cloud"
cs_subparser_help = "Cloud Status Subcommands - Get tactical data from the cloud"

### AWS
cs_aws_subparser = "aws"
cs_aws_subparser_help ="Set AWS-related settings"
aws_cs_subparser_help = "Set AWS-related settings"

ir_aws_get_iam_users_argument = "--iam-users"
ir_aws_get_iam_users_help = "Get a list of IAM Users with tactical data needed for IR"

ir_aws_get_iam_user_argument = "--get-user"
ir_aws_get_iam_user_help = "Get tactical data from an IAM User"

ir_aws_get_iam_role_argument = "--get-role"
ir_aws_get_iam_role_help = "Get tactical data from an IAM Role"

ir_aws_get_access_key_argument = "--access-keys"
ir_aws_get_access_key_help = "Get a all access keys from the AWS Account"

ir_aws_get_user_access_key_argument = "--user-access-keys"
ir_aws_get_user_access_key_help = "Get Access Keys from an specific IAM User"

ir_aws_get_ec2_instances_argument = "--ec2-instances"
ir_aws_get_ec2_instances_help = "Get a list of EC2 instances from the specified region"

ir_aws_get_ec2_instances_all_argument = "--all"
ir_aws_get_ec2_instances_all_help = "Get data from all regions"

ir_aws_get_ec2_instance_profile_argument = "--ec2-instance-profile"
ir_aws_get_ec2_instance_profile_help = "Get the instance profile data from an EC2 instance"

ir_aws_get_ec2_security_groups_argument = "--security-groups"
ir_aws_get_ec2_security_groups_help = "Get all the security groups fron an EC2 instance"

ir_aws_get_lambda_functions_argument = "--lambda-functions"
ir_aws_get_lambda_functions_help = "List lambda functions in an account and region"

ir_aws_get_lambda_data_argument = "--lambda-data"
ir_aws_get_lambda_data_help = "Get tactical data from a lambda function, like env-vars"

ir_aws_get_buckets_argument = "--buckets"
ir_aws_get_buckets_help = "Get the list of s3 buckets from an account"

ir_aws_get_public_buckets_argument = "--public-buckets"
ir_aws_get_public_buckets_help = "Get public s3 buckets"

ir_aws_get_public_objects_argument = "--public-objects"
ir_aws_get_public_objects_help = "Get public s3 objects from a bucket"

ir_aws_get_eks_clusters_argument = "--eks-clusters"
ir_aws_get_eks_clusters_help = "Get a list of EKS Clusters"

ir_aws_get_eks_public_endpoints_argument = "--eks-public-endpoints"
ir_aws_get_eks_public_endpoints_help = "From the eks clusters get only the public endpoints"

ir_aws_get_eks_log_status_argument = "--eks-log-status"
ir_aws_get_eks_log_status_help = "Get details about the logging configuration in the eks cluster"

ir_aws_get_rds_databases_argument = "--rds-databases"
ir_aws_get_rds_databases_help = "Get a list of RDS databases"

ir_aws_get_rds_log_status_argument = "--rds-log-status"
ir_aws_get_rds_log_status_help = "Get details about the logging configuration in an rds instance"

ir_aws_get_rds_security_groups_argument = "--rds-security-groups"
ir_aws_get_rds_security_groups_help = "Get RDS Security Groups"

ir_aws_get_rds_public_access_argument = "--rds-public-access"
ir_aws_get_rds_public_access_help = "Understand if a RDS Database is public"

ir_aws_get_aws_all_argument = "--aws-all"
ir_aws_get_aws_all_help = ""


# INCIDNET RESPONSE
## IR SUBPARSER
ir_cmd = "ir"
ir_help = "Incident Response Subcommands - Disable keys, remove users, delete instances and much more!"
ir_subparser_help = "Incident Response Subcommands - Disable keys, remove users, delete instances and much more!"

### AWS
ir_aws_subparser = "aws"
ir_aws_subparser_help ="Set AWS-related settings"
aws_ir_subparser_help = "Set AWS-related settings"

#### DISABLE
ir_aws_disable_subparser = "disable"
ir_aws_disable_help = "Respond to an attack disabling access keys, console login from user, s3 public access, etc."

ir_aws_disable_access_key_argument = "--access-key"
ir_aws_disable_access_key_help = "Disables an AWS Access Key, you must also specify the IAM User"

ir_aws_disable_aws_user_access_key_argument = "--user-access-keys"
ir_aws_disable_aws_user_access_key_help = "Disables all access key from a user"

ir_aws_disable_aws_user_console_login_argument = "--console-login"
ir_aws_disable_aws_user_console_login_help = "Disables the console access permission of a user"

ir_aws_disable_aws_s3_public_argument = "--s3-public-access"
ir_aws_disable_aws_s3_public_help = "Make a public bucket private"

ir_aws_disable_aws_object_public_argument = "--object-public-access"
ir_aws_disable_aws_object_public_help = "Make a public object private"

ir_aws_disable_aws_eks_public_argument = "--eks-public-access"
ir_aws_disable_aws_eks_public_help = "Make a public eks cluster endpoint private"

ir_aws_disable_aws_rds_public_argument = "--rds-public-access"
ir_aws_disable_aws_rds_public_help = "Make a rds database private"

#### DELETE
ir_aws_delete_subparser = "delete"
ir_aws_delete_help = "Respond to an attack by removing the compromised asset"

ir_aws_delete_iam_user_argument = "--iam-user"
ir_aws_delete_iam_user_help = "Deletes the iam user"

ir_aws_delete_iam_group_argument = "--iam-group"
ir_aws_delete_iam_group_help = "Deletes an IAM Group"

ir_aws_delete_iam_group_policies_argument = "--group-policies"
ir_aws_delete_iam_group_policies_help = "Deletes IAM Access Policies from an IAM Group"

ir_aws_delete_iam_role_argument = "--role"
ir_aws_delete_iam_role_help = "Deletes an IAM role"

ir_aws_delete_instance_profile_argument = "--instance-profile"
ir_aws_delete_instance_profile_help = "Deletes an IAM Instance profile from an EC2 instances"

ir_aws_delete_lambda_role_argument = "--lambda-role"
ir_aws_delete_lambda_role_help = "Delete Lambda Function's role"

ir_aws_delete_lambda_argument = "--lambda-function"
ir_aws_delete_lambda_help = "Delete the lambda function"

ir_aws_delete_ec2_instance_argument = "--ec2-instance"
ir_aws_delete_ec2_instance_help = "Terminate an EC2 instance"

#### RESPOND
ir_aws_respond_subparser = "respond"
ir_aws_respond_help = "Respond to an incident with more specific actions"

ir_aws_respond_acquire_volume_image_argument = "--acquire-volume-image"
ir_aws_respond_acquire_volume_image_help = "Make snapshots of the volumes of an ec2 instance"

ir_aws_respond_enable_ec2_termination_protection_argument = "--enable-ec2-termination-protection"
ir_aws_respond_enable_ec2_termination_protection_help = "Makes an EC2 instance more difficult to terminate"

ir_aws_respond_tag_ec2_forensics_argument = "--tag-ec2-forensics"
ir_aws_respond_tag_ec2_forensics_help = "Add the tag 'ec2-forensic' to the instance"

ir_aws_respond_isolate_ec2_instance_argument = "--isolate-ec2-instance"
ir_aws_respond_isolate_ec2_instance_help = "Adds a Forensic security group to the instance, then removes all others and creates a nacl to block existing connections"

ir_aws_respond_enable_eks_logs_argument = "--enable-eks-logs"
ir_aws_respond_enable_eks_logs_help = "Enables logs in an eks cluster"

ir_aws_respond_enable_rds_deletion_protection_argument = "--enable-rds-deletion-protection"
ir_aws_respond_enable_rds_deletion_protection_help = "Makes a rds more difficult to terminate"


## GENERIC MAGIC LINKS
### AWS
aws_profile_argument = "--profile"
aws_profile_help = "AWS Profile to authenticate to the AWS Account"

aws_region_argument = "--region"
aws_region_help = "AWS Region to authenticate to the AWS Account"
aws_s3_log = "s3"
aws_event_history_log = "event_history"
aws_guardduty_log = "guardduty"
aws_cloudwatch_log = "cloudwatch"
aws_iam_user = "--iam-user"
aws_iam_user_help = "Target an IAM User"
aws_bucket = "--bucket"
aws_bucket_help = "Targets an S3 Bucket"
aws_instance_id = "--instance-id"
aws_instance_id_help = "Target an EC2 instance"

### TOKEN
github_org_argument = "--org"
github_org_help ="Github Organization to get logs from"

github_ent_argument = "--ent"
github_ent_help ="Github Enterprise to get logs from"

github_token_argument = "--token"
github_token_help ="Github Access Token"

### DATE
default_start_date = "2000-01-01"
default_end_date = "2999-01-01"

start_date_argument = "--start_date"
start_date_help = "Start date to retrieve logs - Ex. 2023-01-01"

end_date_argument = "--end_date"
end_date_help = "End date to retrieve logs - Ex. 2023-01-01"

log_retriever_default_file_name = "dredge_log_retriever"
reporter_default_filename = "dredge_reporter.csv"