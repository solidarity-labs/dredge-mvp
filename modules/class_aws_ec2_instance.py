from modules.class_aws_security_group import SecurityGroup
import time
import random

class EC2Instance:
    def __init__(self, session, instance_id, region='us-east-1'):
        ec2_client = session.client('ec2', region)

        # Retrieve the account ID
        self.account_id = session.client('sts').get_caller_identity()['Account']

        # Retrieve the region
        self.region = region

        # Retrieve the EC2 instance attributes
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        try:
            self.subnet_id = instance['SubnetId']
        except KeyError as e:
            self.subnet_id = []

        self.vpc_id = instance['VpcId']

        # Retrieve the EC2 instance name
        tags = instance.get('Tags', [])
        self.name = next((tag['Value'] for tag in tags if tag['Key'] == 'Name'), None)
        self.instance_id = instance_id
        self.dangerous = False  # Placeholder value, modify based on your requirements
        self.public_ip = instance.get('PublicIpAddress')
        self.instance_metadata_v1 = instance['MetadataOptions']['HttpTokens'] == 'optional'
        self.termination_protection = instance.get('DisableApiTermination', {}).get('Value')
        self.shutdown_behavior = instance.get('InstanceInitiatedShutdownBehavior')
        self.volumes = instance.get('BlockDeviceMappings', [])
        self.ssh_key = instance.get('KeyName')
        self.iam_role = instance.get('IamInstanceProfile', {}).get('Arn')
        self.hibernation_behavior = instance.get('HibernationOptions', {}).get('Configured')

        sgs = instance.get('SecurityGroups', [])
        security_groups = []
        for sg in sgs:
            security_group = SecurityGroup.constructor(session, sg['GroupId'], self.region)
            security_groups.append(security_group)
        self.security_groups = security_groups

    def terminate_ec2_instance(self, session):
        ec2_client = session.client('ec2', self.region)
        response = ec2_client.terminate_instances(InstanceIds=[self.instance_id])

        if 'TerminatingInstances' in response:
            instance = response['TerminatingInstances'][0]
            instance_id = instance['InstanceId']
            current_state = instance['CurrentState']['Name']
            previous_state = instance['PreviousState']['Name']
            print(
                f"Instance {instance_id} terminated. Previous state: {previous_state}. Current state: {current_state}")
        else:
            print(f"Failed to terminate instance {self.instance_id}")
    
    
    def acquire_EC2_instance_profile(self, session):
        ec2_client = session.client('ec2')

        response = ec2_client.describe_instances(
            InstanceIds=[self.instance_id]
        )

        reservations = response['Reservations']
        if not reservations:
            print(f"No instance found with ID: {self.instance_id}")
            return

        instance = reservations[0]['Instances'][0]
        if 'IamInstanceProfile' not in instance:
            print(f"No instance profile associated with instance ID: {self.instance_id}")
            return

        instance_profile = instance['IamInstanceProfile']
        instance_profile_name = instance_profile['Arn'].split('/')[-1]
        instance_profile_arn = instance_profile['Arn']
        print(f"Instance profile for instance ID {self.instance_id}: {instance_profile_name}")
        self.instance_profile_name = instance_profile_name
        self.instance_profile_arn = instance_profile_arn

    def removeInstanceProfile(self, session):
        iam_client = session.client('iam')

        # Detach the instance profile from the instance
        try:
            response = iam_client.remove_role_from_instance_profile(
                InstanceProfileName=self.instance_profile_name,
                RoleName=self.instance_profile_name
            )

            print(f"- Instance profile {self.instance_profile_arn} detached from instance")

        except Exception as e:
            print(e)

        response = iam_client.delete_instance_profile(
            InstanceProfileName=self.instance_profile_name
        )

        print(f'- Instance profile {self.instance_profile_name} deleted')

    def acquire_ec2_volume_images(self, session):
        ec2_client = session.client('ec2')
        snapshot_ids = []
        for volume in self.volumes:
            response = ec2_client.create_snapshot(
                Description='SNAPSHOT_CREATION',
                VolumeId=volume['Ebs']['VolumeId']
            )
            snapshot_ids.append(response['SnapshotId'])
            print(f"- Snapshot ID {response['SnapshotId']} created for volume ID {volume['Ebs']['VolumeId']}, "
                  f"device name {volume['DeviceName']}")

        return snapshot_ids

    def enable_ec2_termination_protection(self, session):
        ec2_client = session.client('ec2')
        response = ec2_client.modify_instance_attribute(
            InstanceId=self.instance_id,
            DisableApiTermination={'Value': False}
        )

        print(f"- Enabled termination protection for instance ID {self.instance_id} {self.name}")

    def tag_ec2_instance(self, session):
        ec2_client = session.client('ec2')
        response = ec2_client.create_tags(
            Resources=[self.instance_id],
            Tags=[
                {
                    'Key': 'forensics',
                    'Value': 'True'
                }
            ]
        )

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print(f"* EC2 instance {self.instance_id} has been tagged with forensics = True.")
        else:
            print(f"!! Failed to tag the EC2 instance {self.instance_id}.")

    def check_ec2_autoscaling(self, session):
        autoscaling_client = session.client('autoscaling')
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[self.instance_id])

        for instance in response['AutoScalingInstances']:
            if instance['InstanceId'] == self.instance_id:
                print(
                    f"- The instance {self.instance_id} is part of the Auto Scaling group: {instance['AutoScalingGroupName']}")
                return True

        print(f"- The instance {self.instance_id} is not part of any Auto Scaling group.")
        return False

    def removeEC2Autoscaling():
        pass

    def deRegisterEC2LB():
        pass

    def isolate_ec2_instance(self, session):
        ec2_client = session.client('ec2')
        print("- Let's retrieve some data: ")
        getSecurityGroups(self.instance_id, session)
        time.sleep(3)
        nacl_id, old_acl_id, subnet_id, vpc_id = getNetworkParameters(self.instance_id, session)
        time.sleep(3)
        print()
        print("- Now we need to create a NACL to block all existing connections. It applies to the whole subnet")
        time.sleep(3)
        nacl_association_id = getNaclAssociationId(subnet_id, session)
        changeNACL(nacl_association_id, nacl_id, subnet_id, session)

        # EC2 Network Isolation with Security Groups
        print()
        print("- Now we will remove all Security Groups and add a new one for forensics tasks")
        time.sleep(3)
        group_name = f'forensic_security_group_{random.randint(1000, 9999)}'
        security_group_id = createForensicSecurityGroup(vpc_id, group_name, session)
        updateSecurityGroups(self.instance_id, security_group_id, session)

        # Restablish Subnet Network connection
        print()
        print("- Now we will restore the network traffic permissions in the subnet")
        time.sleep(3)
        nacl_association_id = getNaclAssociationId(subnet_id, session)
        changeNACL(nacl_association_id, old_acl_id, subnet_id, session)


# NETWORKING DATA
def getNetworkParameters(instance_id, session):
    ec2_client = session.client('ec2')

    try:
        response = ec2_client.describe_instances(
            InstanceIds=[instance_id]
        )
        subnet_id = response['Reservations'][0]['Instances'][0]['SubnetId']
        vpc_id = response['Reservations'][0]['Instances'][0]['VpcId']
        print(f"VPC ID for instance {instance_id}: {vpc_id}")
        print(f"Subnet ID for instance {instance_id}: {subnet_id}")

    except Exception as e:
        print(f"Error getting VPC ID or Subnet ID: {e}")
        return None

    # Creates NACL ID
    nacl_id = naclCreation(vpc_id, session)

    # Add NACL ID to Block all traffic (It affects to the subnet)
    old_acl_id = getSubnetACLId(subnet_id, session)

    return nacl_id, old_acl_id, subnet_id, vpc_id


def getNaclAssociationId(subnet_id, session):
    ec2_client = session.client('ec2')

    try:
        response = ec2_client.describe_network_acls(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [subnet_id]
                }
            ]
        )

        # Check if there are any Network ACL associations for the subnet
        if response['NetworkAcls']:
            nacl_association_id = response['NetworkAcls'][0]['Associations'][0]['NetworkAclAssociationId']
            print(f"- Network ACL Association ID: {nacl_association_id}")
        else:
            print("- No Network ACL association found for the subnet.")
    except Exception as e:
        print(f"!! Error getting Network ACL association ID: {e}")

    return nacl_association_id


def naclCreation(vpc_id, session):
    ec2_client = session.client('ec2')

    try:
        # Create the Network ACL
        response = ec2_client.create_network_acl(
            VpcId=vpc_id
        )
        nacl_id = response['NetworkAcl']['NetworkAclId']
        print(f"* Network ACL created with ID: {nacl_id}")

        # Create entries to block all inbound and outbound traffic
        entries = [
            {
                'CidrBlock': '0.0.0.0/0',
                'Egress': True,
                'Protocol': '-1',
                'RuleAction': 'deny',
                'RuleNumber': 100
            },
            {
                'CidrBlock': '0.0.0.0/0',
                'Egress': False,
                'Protocol': '-1',
                'RuleAction': 'deny',
                'RuleNumber': 100
            }
        ]

        # Add the entries to the Network ACL
        for entry in entries:
            ec2_client.create_network_acl_entry(
                NetworkAclId=nacl_id,
                **entry
            )

        print("* Inbound and outbound traffic blocked in the Network ACL.")
        return nacl_id

    except Exception as e:
        print(f"!! Error creating Network ACL: {e}")


def changeNACL(nacl_association_id, new_nacl_id, subnet_id, session):
    ec2_client = session.client('ec2')

    try:
        response = ec2_client.replace_network_acl_association(
            AssociationId=nacl_association_id,
            NetworkAclId=new_nacl_id
        )
        print(f"- Replaced Network ACL for Subnet '{subnet_id}' with '{new_nacl_id}' successfully.")
    except Exception as e:
        print(f"!! Error replacing Network ACL: {e}")


def getSubnetACLId(subnet_id, session):
    ec2_client = session.client('ec2')

    try:
        response = ec2_client.describe_network_acls(
            Filters=[
                {'Name': 'association.subnet-id', 'Values': [subnet_id]}
            ]
        )
        if response['NetworkAcls']:
            acl_id = response['NetworkAcls'][0]['NetworkAclId']
            print(f"Network ACL ID for Subnet '{subnet_id}': {acl_id}")
            return acl_id
        else:
            print(f"- No Network ACL found for Subnet '{subnet_id}'")
    except Exception as e:
        print(f"!! Error retrieving Network ACL ID: {e}")


def createForensicSecurityGroup(vpc_id, group_name, session):
    try:
        ec2_client = session.client('ec2')

        response = ec2_client.create_security_group(
            GroupName=group_name,
            Description='Empty Security Group for network isolation',
            VpcId=vpc_id
        )

        security_group_id = response['GroupId']

        # Revoke all outbound rules
        revokation = ec2_client.revoke_security_group_egress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )

        print(f"* Created security group {group_name} ID: {security_group_id}")
        return security_group_id

    except Exception as e:
        print(f"!! Error creating security group: {e}")


def updateSecurityGroups(instance_id, new_security_group_ids, session):
    ec2_client = session.client('ec2')
    try:
        response = ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[new_security_group_ids]
        )

        print(f"* Removed security groups of instance {instance_id}")
        print(f"* Added forensic security group to instance {instance_id}")
    except Exception as e:
        print(f"!! Error changing security groups: {e}")


def getSecurityGroups(instance_id, session):
    ec2_client = session.client('ec2')

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if 'Reservations' in response and len(response['Reservations']) > 0:
            instance = response['Reservations'][0]['Instances'][0]
            security_groups = instance['SecurityGroups']

            if len(security_groups) > 0:
                print(f'EC2 instance {instance_id} has {len(security_groups)} Security Groups:')
                for group in security_groups:
                    print(f"Security Group ID: {group['GroupId']} - Name: {group['GroupName']}")
            else:
                print(f"- No security groups associated with instance {instance_id}")
        else:
            print(f"Instance {instance_id} not found")
    except Exception as e:
        print(f"!! Error retrieving security groups: {e}")