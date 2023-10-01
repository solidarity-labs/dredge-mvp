from pprint import pprint
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from datetime import datetime, timedelta
from utils.vars import dangerous_k8s_criteria

class KubernetesCluster:
    def __init__(self, kubeconfig_path=None):
        if kubeconfig_path:
            config.load_kube_config(kubeconfig_path)
        else:
            config.load_kube_config()

        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.events_api = client.EventsV1Api()

    def list_namespaces(self):
        namespace_list = self.v1.list_namespace()
        return [namespace.metadata.name for namespace in namespace_list.items]


    def get_namespace_events(self, namespace):
        try:
            since_time = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

            events = self.v1.list_namespaced_event(namespace)
            print(events)
            exit(0)
            filtered_events = [event for event in events.items if self.is_event_within_time(event, since_time)]
            
            return filtered_events
        except KeyError as e:
            return f"Error retrieving events in namespace {namespace}: {e}"


    def is_event_within_time(self, event, since_time):
        event_time = event.event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        return event_time >= since_time


    def list_pods(self, namespace):
        pod_list = self.v1.list_namespaced_pod(namespace)
        pods = []
        for pod in pod_list.items:
            pod_name = pod.metadata.name
            pods.append(pod_name)

        return(pods)

    def list_secrets(self, namespace):
        try:
            secrets_list = self.v1.list_namespaced_secret(namespace)
            secrets = []
            for secret in secrets_list.items:
                secrets.append(secret.metadata.name)
            return secrets
        
        except ApiException as e:
            return f"Error retrieving secrets in namespace {namespace}: {e}"


    def list_service_accounts(self, namespace):
        try:
            service_accounts_list = self.v1.list_namespaced_service_account(namespace)
            return [sa.metadata.name for sa in service_accounts_list.items]
        except ApiException as e:
            return f"Error retrieving service accounts in namespace {namespace}: {e}"

    
    def get_pod_logs(self, namespace, pod_name, container_name=None, tail_lines=10):
        try:
            if container_name:
                logs = self.v1.read_namespaced_pod_log(name=pod_name, namespace=namespace, container=container_name, tail_lines=tail_lines)
            else:
                logs = self.v1.read_namespaced_pod_log(name=pod_name, namespace=namespace, tail_lines=tail_lines)
            return logs
        except ApiException as e:
            return f"Error retrieving logs for pod {pod_name} in namespace {namespace}: {e}"


    def get_secret_data(self, namespace, secret_name):
        try:
            secret = self.v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            return secret.data
        except ApiException as e:
            return f"Error retrieving data from secret {secret_name} in namespace {namespace}: {e}"


    def get_roles_for_service_account(self, namespace, service_account_name):
        roles = []
        # List RoleBindings in the namespace

        role_bindings = self.rbac.list_namespaced_role_binding(namespace)

        for role_binding in role_bindings.items:
            subjects = role_binding.subjects
            for subject in subjects:
                if subject.name == service_account_name and subject.kind == "ServiceAccount":
                    role_ref = role_binding.role_ref
                    role_dict = {}
                    role_dict['type'] = 'role'
                    role_dict['name'] = role_ref.name
                    roles.append(role_dict)

        # List ClusterRoleBindings
        cluster_role_bindings = self.rbac.list_cluster_role_binding()
        
        for cluster_role_binding in cluster_role_bindings.items:
            if cluster_role_binding.subjects:
                subjects = cluster_role_binding.subjects
                for subject in subjects:
                    if subject.name == service_account_name and subject.kind == "ServiceAccount":
                        role_ref = cluster_role_binding.role_ref

                        role_dict = {}
                        role_dict['type'] = 'clusterRole'
                        role_dict['name'] = role_ref.name

                        roles.append(role_dict)

        return roles

    
    def get_role_permissions(self, namespace, role_name):
        permissions = []

        try:
            # Get the Role or ClusterRole
            role = self.rbac.read_namespaced_role(name=role_name, namespace=namespace)

            # Extract the rules from the Role or ClusterRole
            for rule in role.rules:
                try:
                    role_rule = {}
                    
                    api_groups = ",".join(rule.api_groups) if rule.api_groups else "*"
                    resources = ",".join(rule.resources) if rule.resources else "*"
                    verbs = ",".join(rule.verbs) if rule.verbs else "*"
                    
                    role_rule['apiGroups'] = api_groups
                    role_rule['resources'] = resources
                    role_rule['verbs'] = verbs
                    permissions.append(role_rule)

                except AttributeError as e:
                    continue

            return permissions

        except Exception as e:
            return f"Error retrieving permissions for Role {role_name} in namespace {namespace}: {e}"


    def get_cluster_role_permissions(self, cluster_role_name):
        permissions = []

        try:
            # Get the ClusterRole
            cluster_role = self.rbac.read_cluster_role(name=cluster_role_name)

            # Extract the rules from the ClusterRole
            for rule in cluster_role.rules:
                try:
                    role_rule = {}

                    api_groups = ",".join(rule.api_groups) if rule.api_groups else "*"
                    resources = ",".join(rule.resources) if rule.resources else "*"
                    verbs = ",".join(rule.verbs) if rule.verbs else "*"

                    role_rule['apiGroups'] = api_groups
                    role_rule['resources'] = resources
                    role_rule['verbs'] = verbs
                    permissions.append(role_rule)

                except AttributeError as e:
                    continue

            return permissions

        except Exception as e:
            return f"Error retrieving permissions for ClusterRole {cluster_role_name}: {e}"


    def detect_dangerous_permissions_role(self, namespace, role_name):
        dangerous_permissions = []
        event = {}

        try:
            # Get the Role or ClusterRole
            role = self.rbac.read_namespaced_role(name=role_name, namespace=namespace)
            # Check if any rules match the dangerous criteria
            for rule in role.rules:
                for criteria in dangerous_k8s_criteria:
                    for k8s_resource in rule.resources:
                        if k8s_resource in criteria['resources']:
                            for k8s_verb in rule.verbs:
                                if k8s_verb in criteria["verbs"]:
                                    event['name'] = role.metadata.name
                                    event['type'] = 'role'
                                    event['dangerous_criteria'] = criteria
                                    dangerous_permissions.append(event)
        
            return dangerous_permissions

        except KeyboardInterrupt as e:
            return f"Error detecting dangerous permissions for Role {role_name} in namespace {namespace}: {e}"

    def detect_dangerous_permissions_cluster_role(self, cluster_role_name):
        dangerous_permissions = []

        event = {}
        
        try:
            # Get the ClusterRole
            cluster_role = self.rbac.read_cluster_role(name=cluster_role_name)
            
            # Check if any rules match the dangerous criteria
            for rule in cluster_role.rules:
                for criteria in dangerous_k8s_criteria:
                    for k8s_resource in rule.resources:
                        if k8s_resource in criteria['resources']:
                            for k8s_verb in rule.verbs:
                                if k8s_verb in criteria['verbs']:
                                    event['name'] = cluster_role.metadata.name
                                    event['type'] = 'clusterRole'
                                    event['dangerous_criteria'] = criteria
                                    dangerous_permissions.append(event)
            
            return dangerous_permissions
        
        except Exception as e:
            return f"Error detecting dangerous permissions for ClusterRole {cluster_role_name}: {e}"


def main():
    k8s = KubernetesCluster()
    print(k8s.get_namespace_events('default'))