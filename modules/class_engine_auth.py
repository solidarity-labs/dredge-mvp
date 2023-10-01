import boto3
import botocore
from google.cloud import logging

class AWSAuth:
    def __init__(self, profile, region):
        self.region = region
        self.profile = profile
        try:
            session = boto3.session.Session(profile_name=f'{profile}',
                                        region_name=f'{region}')
            self.session = session
        except botocore.exceptions.ProfileNotFound as e:
            raise(e)


class GCPAuth:
    def __init__(self, cred_file = None):
        self.cred_file = cred_file

        if cred_file:
            self.client = logging.Client.from_service_account_json(cred_file)
        
        else:
            self.client = logging.Client()

