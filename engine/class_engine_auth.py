import boto3
import botocore

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
