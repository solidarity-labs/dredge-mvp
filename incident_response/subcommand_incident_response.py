from incident_response.engine_incident_response import disable_aws_access_key, disable_all_user_access_keys, disable_user_console_login, disable_object_public_access, disable_eks_public_access
from incident_response.engine_incident_response import disable_s3_public_access, disable_rds_public_access,delete_iam_user, delete_iam_group, detach_group_policies, delete_iam_role    
from incident_response.engine_incident_response import delete_instance_profile, delete_ec2_instance, delete_lambda_role, delete_lambda_function, acquire_volume_image
from incident_response.engine_incident_response import enable_ec2_termination_protection, tag_ec2_forensics, isolate_ec2_instance, enable_eks_logs, enable_rds_deletion_protection
from utils.utils import aws_session_validator
import utils.constants

def incident_response_subcommand(args):
    # INCIDENT RESPOND    
    # AWS SUBBPARSER
    args, session = aws_session_validator(args)
    if args.ir_subcommand == utils.constants.ir_aws_subparser:
        ## 'DISABLE' AWS SUBPARSER
        if args.aws_ir_subcommand == utils.constants.ir_aws_disable_subparser:

            if args.iam_user and not args.access_key:
                disable_user_console_login(session,args.iam_user)
                disable_all_user_access_keys(session, args.user_access_keys)

            if args.access_key and args.iam_user:
                disable_aws_access_key(session, args.iam_user, args.access_key)
            
            if args.access_key and not(args.iam_user):
                args.iam_user = input("Input IAM User owner of that key: ")
                disable_aws_access_key(session, args.iam_user, args.access_key)

            elif args.user_access_keys:
                disable_all_user_access_keys(session, args.user_access_keys)

            elif args.console_login and args.iam_user:
                disable_user_console_login(session,args.iam_user)

            elif args.s3_public_access:
                disable_s3_public_access(session, args.s3_public_access)
            
            elif args.object_public_access and args.bucket:
                disable_object_public_access(session, args.bucket, args.object_public_access)

            elif args.eks_public_access:
                disable_eks_public_access(session, args.eks_public_access, args.region)

            elif args.rds_public_access:
                disable_rds_public_access(session, args.rds_public_access, args.region)

        elif args.aws_ir_subcommand == 'delete':
        
            if args.iam_user:
                delete_iam_user(session, args.iam_user)
                
            elif args.iam_group:
                delete_iam_group(session, args.iam_group)

            elif args.group_policies:
                detach_group_policies(session, args.group_policies)

            elif args.role:
                delete_iam_role(session, args.role)

            elif args.instance_profile:
                delete_instance_profile(session, args.instance_profile, args.region)

            elif args.ec2_instance:
                delete_ec2_instance(session, args.ec2_instance, args.region)

            elif args.lambda_role:
                delete_lambda_role(session, args.lambda_role, args.region)

            elif args.lambda_function:
                delete_lambda_function(session, args.lambda_function, args.region)

        elif args.aws_ir_subcommand == 'respond':
            if args.acquire_volume_image and args.instance_id:
                acquire_volume_image(session, args.instance_id, args.region)

            elif args.enable_ec2_termination_protection:
                enable_ec2_termination_protection(session, args.enable_ec2_termination_protection, args.region)

            elif args.tag_ec2_forensics:
                tag_ec2_forensics(session, args.tag_ec2_forensics, args.region)
            
            elif args.isolate_ec2_instance:
                isolate_ec2_instance(session, args.isolate_ec2_instance, args.region)

            elif args.enable_eks_logs:
                enable_eks_logs(session, args.enable_eks_logs, args.region)

            elif args.enable_rds_deletion_protection:
                enable_rds_deletion_protection(session, args.enable_rds_deletion_protection, args.region)


