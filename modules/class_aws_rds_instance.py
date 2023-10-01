import boto3

class RDSInstance:
    def __init__(self, session, db_instance_identifier, region='us-east-1'):

        rds_client = session.client('rds', region)
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        db_instance = response['DBInstances'][0]
        self.region = region
        self.db_instance_identifier = db_instance['DBInstanceIdentifier']
        self.db_instance_class = db_instance['DBInstanceClass']
        self.engine = db_instance['Engine']
        self.engine_version = db_instance['EngineVersion']
        self.storage_type = db_instance['StorageType']
        self.allocated_storage = db_instance['AllocatedStorage']
        self.availability_zone = db_instance['AvailabilityZone']
        self.multi_az = db_instance['MultiAZ']
        self.publicly_accessible = db_instance['PubliclyAccessible']
        self.tags = db_instance.get('TagList', [])

        self.encryption = db_instance.get('StorageEncrypted', False)
        self.log_status = db_instance.get('EnabledCloudwatchLogsExports', [])
        self.delete_protection = db_instance.get('DeletionProtection', False)

        if isinstance(db_instance.get('VpcSecurityGroups', []), list):
            self.security_groups = db_instance.get('VpcSecurityGroups', [])
        else:
            self.security_groups = [db_instance.get('VpcSecurityGroups', [])]


    # TESTING REQUIRED
    @staticmethod
    def block_RDS_public_access(db_instance_identifier, session):
        # Create an RDS client using the session
        rds_client = session.client('rds')

        # Disable public access for the DB instance
        try:
            response = rds_client.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                PubliclyAccessible=False
            )
            print(f"Public access is disabled for RDS database '{db_instance_identifier}'"
                  f" - Aplying the configuration can have some seconds of delay")
        except Exception as e:
            print(e)

        return response

    @staticmethod
    def enableRDSDeletionProtection(db_instance_identifier, session):
        rds_client = session.client('rds')
        # Enable deletion protection for the DB instance
        try:
            response = rds_client.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                DeletionProtection=True
            )
            print(f"Deletion protection is now enabled for RDS database {db_instance_identifier}")
        except Exception as e:
            print(e)

        return response
