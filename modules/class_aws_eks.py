import boto3
import time

class EKSCluster:
    def __init__(self, session, cluster_name, region='us-east-1'):
        eks_client = session.client('eks', region)

        response = eks_client.describe_cluster(name=cluster_name)
        self.region = region
        self.cluster_name = response['cluster']['name']
        self.version = response['cluster']['version']
        self.status = response['cluster']['status']
        self.endpoint = response['cluster']['endpoint']
        self.role_arn = response['cluster']['roleArn']
        self.vpc_id = response['cluster']['resourcesVpcConfig']['vpcId']
        self.subnets = response['cluster']['resourcesVpcConfig']['subnetIds']

        self.log_status = None
        if 'logging' in response['cluster']:
            self.log_status = response['cluster']['logging'].get('clusterLogging', [])

    def enable_eks_logs(self, session):
        eks_client = session.client('eks')

        print("- Let's check which logs we need to enable")
        log_types = get_eks_log_status(self.cluster_name, session)

        # Enable logging for the EKS cluster
        if log_types == []:
            print('* Log type are enabled! We are good :)')

        else:
            print(f'- Trying to enable logs for {log_types} types')
            try:
                response = eks_client.update_cluster_config(
                    name=self.cluster_name,
                    logging={
                        'clusterLogging': [
                            {
                                'types': log_types,
                                'enabled': True
                            }
                        ]
                    }
                )
                time.sleep(3)
                if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    print(
                        f"* The Log Enabling request was executed successfully, now you'll need to wait "
                        f"and check if logs were enabled for the '{self.cluster_name}' cluster")

            except Exception as e:
                print(e)

    def block_eks_public_endpoint(self, session):
        # Create an EKS client using the session
        eks_client = session.client('eks')
        # Update the EKS cluster configuration to set the endpoint to private
        try:
            response = eks_client.update_cluster_config(
                name=self.cluster_name,
                resourcesVpcConfig={
                    'endpointPublicAccess': False,
                    'endpointPrivateAccess': True
                }
            )
            time.sleep(3)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print(f"* The Block Public Endpoint request was executed successfully for {self.cluster_name}, "
                      f"now you must wait for the cluster tu complete the configuration setup")

        except Exception as e:
            print(e)

def get_eks_log_status(cluster_name, session):
    # Create an EKS client using the session
    eks_client = session.client('eks')
    not_enabled_logs = []

    try:
        # Describe the EKS cluster to get log configuration information
        response = eks_client.describe_cluster(name=cluster_name)

        # Get the log configuration status
        log_configuration = response['cluster']['logging']['clusterLogging']
        for log in log_configuration:
            if log['enabled']:
                for enabled_type in log['types']:
                    print(f'EKS Cluster {cluster_name} has {enabled_type} log ENABLED')

            elif log['enabled'] == False:
                for disabled_type in log['types']:
                    print(f'EKS Cluster {cluster_name} has {disabled_type} log DISABLED')
                    not_enabled_logs.append(disabled_type)

        return not_enabled_logs

    except Exception as e:
        print(e)