import re
import datetime
import tqdm
import os
import botocore

class S3Bucket:
    '''
    Attributes:
        - bucket_name
        - region
        - tags
        - block_public_access
        - creation_date
        - public_objects

    IR Methods:
        - Block S3 public Access
        - Block Object public Access
    '''
    def __init__(self, session, bucket_name):
        self.bucket_name = bucket_name

        s3_client = session.client('s3')

        # Get bucket location
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        self.region = response['LocationConstraint']

        # Get bucket tags
        try:
            response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            self.tags = response.get('TagSet', [])
        except botocore.exceptions.ClientError as e:
            self.tags = None

        # Get bucket ACL
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        self.block_public_access = response.get('PublicAccessBlockConfiguration', {}).get('RestrictPublicBuckets', False)

        # Get bucket creation date
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        self.creation_date = response['ResponseMetadata']['HTTPHeaders']['date']

    def get_public_objects(self, session):
        s3_client = session.client('s3')
        response = s3_client.list_objects_v2(Bucket=self.bucket_name)
        objects = response.get('Contents', [])

        public_objects = []
        object = {}

        for obj in objects:
            response = s3_client.get_object_acl(Bucket=self.bucket_name, Key=obj['Key'])
            grants = response.get('Grants', [])

            for grant in grants:
                grantee = grant.get('Grantee', {})
                grantee_type = grantee.get('Type', '')

                if grantee_type == 'Group' and grantee.get('URI', '') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    object['key'] = obj['Key']
                    object['LastModified'] = obj['LastModified']
                    object['Size'] = obj['Size']
                    public_objects.append(object)
                    break

        self.public_objects = public_objects

    def download_bucket_objects(self, session, start_date, end_date, destination_path, file_name = False):
        s3_client = session.client('s3')
        objects = s3_client.list_objects_v2(Bucket=self.bucket_name)

        try:
            os.mkdir(destination_path)
        except FileExistsError as e:
            pass

        start_date = datetime.date.fromisoformat(start_date)
        end_date = datetime.date.fromisoformat(end_date)
        response = objects['Contents']
        counter = 0
        for obj in response:
            final_destination = ''
            if file_name:
                final_destination = os.path.join(destination_path, f'{self.bucket_name}_{file_name}_{counter}.log.gz')

            else:
                final_destination = os.path.join(destination_path, f'{self.bucket_name}_{counter}.log.gz')
            counter += 1
            match = re.search(r'\d{4}/\d{2}/\d{2}', obj['Key'])
            try:
                date = datetime.datetime.strptime(match.group(), '%Y/%m/%d').date()
                if start_date <= date <= end_date:
                    try:
                        s3_client.download_file(self.bucket_name,
                                         obj['Key'],
                                         final_destination)
                        print(f"{obj['Key']} -> {final_destination}")

                    except FileNotFoundError as e:
                        print(e)
                        exit(0)
                    except KeyboardInterrupt as e:
                        print(e)
                        exit(0)
                else:
                    continue

            except AttributeError as e:
                pass

    #TESTING REQUIRED
    @staticmethod
    def block_s3_bucket_public_access(bucket_name, session):
        s3_client = session.client('s3')

        response = s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print(f"* Public access blocked for bucket: {bucket_name}")
        else:
            print(f"* Failed to block public access for bucket: {bucket_name}")

        return response

    @staticmethod
    def block_s3_object_public_access(bucket_name, object_key, session):
        s3_client = session.client('s3')

        response = s3_client.put_object_acl(
            Bucket=bucket_name,
            Key=object_key,
            ACL='private'
        )

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print(f"* Public access blocked for s3://{bucket_name}/{object_key}")
        else:
            print(f"* Failed to block public access for s3://{bucket_name}/{object_key}")

        return response