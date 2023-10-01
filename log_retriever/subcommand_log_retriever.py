import botocore
import boto3
import utils.constants
from utils.utils import validate_aws_region, args_date_validator
from log_retriever.class_engine_log_retriever import LogRetriever
from modules.class_github import Github


def log_retriever_subcommand(args):
    start_date, end_date = args_date_validator(args)            
    log_retriever = LogRetriever(start_date, end_date, ".", utils.constants.default_file_name)
    log_retriever.destination_path = utils.constants.default_output_folder
    log_retriever.output_file_name = utils.constants.default_file_name
    
    #AWS LOG RETRIEVER
    if args.lr_subcommand == utils.constants.lr_aws_subparser:
        if not validate_aws_region(args.region):
            print(f"'{args.region}' is not a valid AWS region.")
            exit(1)
    
        try:
            session = boto3.session.Session(profile_name=f'{args.profile}', region_name=f'{args.region}')
        except botocore.exceptions.ProfileNotFound as e:
            raise(e)
        
        #S3 BUCKET LOG RETRIEVER
        if args.log == utils.constants.aws_s3_log:
            bucket = args.target               
            try:
                log_retriever.get_s3_logs(session, bucket)
            except botocore.exceptions.ParamValidationError as e:
                print(e)
            
            except KeyboardInterrupt as e:
                print(e)

        #EVENT HISTORY LOG RETRIEVER
        elif args.log == utils.constants.aws_event_history_log:

            try:
                log_retriever.get_event_history_logs(session)
            except botocore.exceptions.ParamValidationError as e:
                print(e)
        
        #GUARDDUTY LOG RETRIEVER
        elif args.log == utils.constants.aws_guardduty_log:
            try:
                log_retriever.get_guardduty_findings(session)
            except botocore.exceptions.ParamValidationError as e:
                print(e)

        #CLOUDWATCH LOG RETRIEVER
        elif args.log == utils.constants.aws_cloudwatch_log:
            try:
                log_retriever.get_cloudwatch_logs(session, args.target)
            except botocore.exceptions.ParamValidationError as e:
                print(e)
    
    #GITHUB LOG RETRIEVER
    elif args.lr_subcommand == utils.constants.lr_github_subparser:
        if args.org:
            github = Github(args.token, args.org)
            log_retriever.get_github_logs(github)    
        elif args.ent:
            github = Github(args.token, None, args.ent)
            log_retriever.get_github_logs(github)

    #K8S LOG RETRIEVER
    elif args.lr_subcommand == utils.constants.lr_k8s_subparser:
        if args.pod:
            k8s_logs = log_retriever.get_k8s_logs(args.namespace, args.pod, args.config)
            print(k8s_logs)

        elif args.events:
            k8s_events = log_retriever.get_k8s_namespace_events(args.namespace, args.config)
            print(k8s_events)

    elif args.lr_subcommand == 'gcp':
        log_retriever.get_gcp_api_logs(args.cred_file, args.start_date, args.end_date)

    log_retriever.json_reporter()
    