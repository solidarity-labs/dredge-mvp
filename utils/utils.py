import utils.constants
import botocore
import boto3
from utils.vars import valid_aws_regions

def validate_aws_region(aws_region):
    return aws_region in valid_aws_regions

def get_enabled_regions(session):
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_regions()

        enabled_regions = []

        for region in response['Regions']:
            region_name = region['RegionName']
            enabled_regions.append(region_name)

        return enabled_regions
    
    except Exception as e:
        print(e)
        exit(1)


def args_date_validator(args):
    try:
        if args.start_date:
            start_date = args.start_date
        else:
            start_date = utils.constants.default_start_date

        if args.end_date:
                end_date = args.end_date
        else:
            end_date = utils.constants.default_end_date
    except AttributeError as e:
        pass

    return start_date, end_date


def aws_session_validator(args):
    ## Set default profile and region if not provided 
    try:
        if not(args.profile):
            args.profile = utils.constants.default_profile
        
        if not(args.region):
            args.region = utils.constants.default_region

        try:
            session = boto3.session.Session(profile_name=f'{args.profile}', region_name=f'{args.region}')
            return session
        
        except botocore.exceptions.ProfileNotFound as e:
            print(e)
            exit(1)
            
        except botocore.exception.ClientError as e:
            print(e)
            exit(1)
    except AttributeError as e:
        print(e)