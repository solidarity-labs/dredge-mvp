import re
import whois
import shodan
import requests
import json
import time
from tqdm import tqdm
from tabulate import tabulate
from utils.vars import dangerous_api_call_dict
from engine.engine_reporter import Reporter
from modules.class_k8s_cluster import KubernetesCluster
from kubernetes.client.exceptions import ApiException


class ThreatHunting:
    def __init__(self):
        self.ips = []
        self.shodan_enriched_ips = []
        self.whois_enriched_ips = []

    # IP ANALYSIS
    def ip_retriever(self, file: str) -> list:
        '''
        :param eventHistoryFile: Text file with the json output, but it can get ips from whatever text you want
        :return: list of unique ips
        '''
        ips = []
        try:
            with open(f'{file}', 'r') as file:
                contents = file.read()
                ip_list = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', contents)
                sorted_ip_list = sorted(set(ip_list))
                for ip in sorted_ip_list:
                    ips.append(ip)
                return ips

        except FileNotFoundError:
            print("File not found.")
        except Exception as e:
            pass


    def whois_enrichment(self, target):
        whois_ip = whois.whois(target)
        if whois_ip['domain_name']:
            whois_ip['ip_address'] = target
            self.whois_enriched_ips.append(whois_ip)
        
        return self.whois_enriched_ips

    # SHODAN
    def shodan_enrichment(self, target, api_key):
        api = shodan.Shodan(api_key)
        try:
            # Lookup the IP address information
            host = api.host(target)
            return host
        
        except shodan.APIError as e:
            return e

    # VIRUSTOTAL
    def vt_analyze_file(self, file_name, vt_key):
        ip_address = self.ip_retriever(file_name)
        results = []
        headers = ['IP', 'ASN', 'ASN_NAME', 'COUNTRY', 'IS_BAD']
        results.append(headers)
        print(f'Processing {len(ip_address)} IPs')   
        for ip in  tqdm(ip_address, desc="Processing", unit="item"):
            results.append(self.vt_ip_scan(ip, vt_key))

        data = tabulate(results, headers="firstrow", tablefmt="fancy_grid")
        file_name = f'vt_analysis' 
        print()
        print(data)
        print()
        reporter = Reporter(data, file_name, True, False, True)
        reporter.csv_reporter()


    def vt_ip_scan(self, ip_address, vt_key):
        # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
        api_key = vt_key

        # IP address you want to scan
        target_ip = ip_address

        # URL for the VirusTotal IP address report endpoint
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{target_ip}'

        # Headers with the API key
        headers = {
            'x-apikey': api_key
        }

        try:
            # Send a GET request to the VirusTotal API
            response = requests.get(url, headers=headers)

            # Check if the request was successful
            if response.status_code == 200:

                data = response.json()
                parsed_data = self.vt_parser(data)
                return parsed_data

            else:
                print(f"Error: {response.status_code} - {response.text}")

        except Exception as e:    
            print(f"Error: {e}")


    def vt_analyze_ip(self, vt_key, ip_address):
        url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'

        # Make a GET request to VirusTotal API
        params = {'apikey': vt_key, 'ip': ip_address}
        response = requests.get(url, params=params)

        # Check the response status code
        if response.status_code == 200:
            json_response = response.json()

            # Print the response from VirusTotal
            print(json_response)

            # Check if the IP address has been analyzed previously
            if 'detected_communicating_samples' in json_response:
                # Print the detected malicious communicating samples
                print('Detected Communicating Samples:')
                for sample in json_response['detected_communicating_samples']:
                    print(f'Sample: {sample["sha256"]}')
                    print(f'Date: {sample["date"]}')
                    print(f'Positives: {sample["positives"]}')
                    print(f'Total: {sample["total"]}\n')
            else:
                print('IP address has not been analyzed previously.')
        else:
            print(f'Request failed with status code {response.status_code}')


    def vt_analyze_domain(self, vt_key, domain):
        # SEND DOMAIN FOR ANALYSIS
        url = f"https://www.virustotal.com/api/v3/urls/{domain}/comments?limit=10"

        headers = {
            "accept": "application/json",
            "x-apikey": vt_key
        }

        response = requests.get(url, headers=headers)

        print(response.text)


    def vt_analyze_hash(self, vt_key, hash):
        url = f'https://www.virustotal.com/vtapi/v2/file/report'

        # Make a GET request to VirusTotal API
        params = {'apikey': vt_key, 'resource': hash}
        response = requests.get(url, params=params)

        # Check the response status code
        if response.status_code == 200:
            json_response = response.json()
            # Check if the file hash has been analyzed previously
            if json_response['response_code'] == 1:
                # Print the detection results
                print('Detection Results:')
                for antivirus, result in json_response['scans'].items():
                    print(f'{antivirus}: {result["result"]}')
            else:
                print('File hash has not been analyzed previously.')
        else:
            print(f'Request failed with status code {response.status_code}')


    def vt_parser(self, data):
        '''
        Headers:
        IP, ASN, ASN_NAME, COUNTRY, IS_BAD
        '''
        # Extract desired information
        try:
            ip = data['data']['id']
        except Exception as e:
            ip = 'None'
        
        try:
            asn = data['data']['attributes']['asn']
        except Exception as e:
            asn = 'None'
        
        try:
            asn_name = data['data']['attributes']['as_owner']
        except Exception as e:
            asn_name = 'None'
        
        try:
            country = data['data']['attributes']['country']
        except Exception as e:
            country = 'None'
        
        try:
            malicious = any(result['category'] == 'malicious' for result in data['data']['attributes']['last_analysis_results'].values())
        except Exception as e:
            malicious = 'None'

        parsed_data = [ip, asn, asn_name, country, malicious]
        return parsed_data

    # AWS
    def get_event_history_alerts(self, session, start_date, end_date, args):
        file_name = 'th_aws_event_history_alerts'
        if args.csv:
            flag = 'csv'
        else:
            flag = '*'

        first = True
        nextToken = ''
        event_history_events = []
        data = []
        headers = ['awsRegion', 'eventName', 'eventSource', 'eventTime', 'sourceIPAddress', 'userAgent', 'accessKeyId'
                  'accessKeyId', 'accountId', 'arn', 'principalId', 'type', 'userName']
        
        data.append(headers)

        while True:
            try:
                client = session.client('cloudtrail')
                if first:
                    cloudtrail_response = client.lookup_events(
                        StartTime=start_date,
                        EndTime=end_date,
                        MaxResults=50,
                    )
                else:
                    cloudtrail_response = client.lookup_events(
                        StartTime=start_date,
                        EndTime=end_date,
                        MaxResults=50,
                        NextToken=nextToken
                    )

                try:
                    for i in cloudtrail_response['Events']:
                        json_cloudtrail_event = json.loads(i['CloudTrailEvent'])
                        if args.ip:
                            if json_cloudtrail_event['sourceIPAddress'] == args.ip:
                                event = aws_event_parser(json_cloudtrail_event)
                                default_hunting_file = f'hunting_ip_{args.ip}'
                                print(event)

                        elif args.access_key: 
                            if json_cloudtrail_event['userIdentity']['accessKeyId'] == args.access_key:
                                event = aws_event_parser(json_cloudtrail_event)
                                default_hunting_file = f'hunting_access_key_{args.access_key}'
                                print(event)

                        elif args.iam_user: 
                            if json_cloudtrail_event['userIdentity']['userName'] == args.iam_user:
                                event = aws_event_parser(json_cloudtrail_event)
                                default_hunting_file = f'hunting_iam_user_{args.iam_user}'
                                print(event)

                        elif args.timeline:
                            event = aws_event_parser(json_cloudtrail_event)
                            default_hunting_file = f'hunting_timeline'
                            print(event)

                        elif args.dangerous_api_calls:
                            if json_cloudtrail_event['eventName'] in dangerous_api_call_dict.keys():
                                event = aws_event_parser(json_cloudtrail_event)
                                event.append(dangerous_api_call_dict[json_cloudtrail_event['eventName']])
                                headers.append('Security Alert Description')
                                default_hunting_file = 'dangerous_api_call'
                                print(event)

                            else:
                                break

                        data.append(event)

                        if args.csv:
                            reporter = Reporter(event, file_name)
                            reporter.csv_reporter()

                except KeyError as e:
                    print(e)
                    continue
                
                except KeyboardInterrupt as e:
                    print(e)

                nextToken = str(cloudtrail_response['NextToken'])
                first = False
            except KeyError as e:
                break


        reporter(data, flag, default_hunting_file)
        return event_history_events


    def detect_k8s_dangerous_permissions(self, args):
        file_name = 'th_k8s_dangerous_permissions'

        if args.csv:
            flag = 'csv'
        else:
            flag = '*'

        k8s = KubernetesCluster()
        headers = ['Namespace', 'Service Account', 'Role Name', 'Role Type', 'Matches Dangerous Criteria']
        data = []
        data.append(headers)
        dangerous_list = []

        if args.role and args.namespace:
            try:
                dangerous_permissions = k8s.detect_dangerous_permissions_role(args.namespace, args.role)
                for event in dangerous_permissions:
                    dangerous_list = [args.namespace, 'N/A', event['type'], event['name'], event['dangerous_criteria']]
                    data.append(dangerous_list)

            except ApiException as e:
                dangerous_permissions = k8s.detect_dangerous_permissions_cluster_role(args.role)
                for event in dangerous_permissions:
                    dangerous_list = [args.namespace, 'N/A', event['type'], event['name'], event['dangerous_criteria']]
                    data.append(dangerous_list)

        elif args.service_account and args.namespace:
            service_accounts = k8s.list_service_accounts(args.namespace)
            for sa in service_accounts:
                roles = k8s.get_roles_for_service_account(args.namespace, sa)
                if roles:
                    for role in roles:
                        if role['type'] == 'role':
                            dangerous_permissions = k8s.detect_dangerous_permissions_role(namespace, role['name'])
                            for event in dangerous_permissions:
                                dangerous_list = [args.namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                data.append(dangerous_list)

                        elif role['type'] == 'clusterRole':
                            dangerous_permissions = k8s.detect_dangerous_permissions_cluster_role(role['name'])
                            for event in dangerous_permissions:
                                dangerous_list = [args.namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                data.append(dangerous_list)
        
        elif args.namespace:
            namespace = args.namespace
            service_accounts = k8s.list_service_accounts(namespace)
            for sa in service_accounts:
                roles = k8s.get_roles_for_service_account(namespace, sa)
                if roles:
                    for role in roles:
                        if role['type'] == 'role':
                            dangerous_permissions = k8s.detect_dangerous_permissions_role(namespace, role['name'])
                            for event in dangerous_permissions:
                                dangerous_list = [namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                data.append(dangerous_list)

                        elif role['type'] == 'clusterRole':
                            dangerous_permissions = k8s.detect_dangerous_permissions_cluster_role(role['name'])
                            for event in dangerous_permissions:
                                dangerous_list = [namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                data.append(dangerous_list)

        elif not args.namespace:
            k8s = KubernetesCluster()
            namespaces = k8s.list_namespaces()

            for namespace in namespaces:
                if args.no_kubesystem:
                    if namespace == 'kube-system':
                        break

                service_accounts = k8s.list_service_accounts(namespace)
                for sa in service_accounts:
                    roles = k8s.get_roles_for_service_account(namespace, sa)
                    if roles:
                        for role in roles:
                            if role['type'] == 'role':
                                dangerous_permissions = k8s.detect_dangerous_permissions_role(namespace, role['name'])
                                for event in dangerous_permissions:
                                    dangerous_list = [namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                    data.append(dangerous_list)

                            elif role['type'] == 'clusterRole':
                                dangerous_permissions = k8s.detect_dangerous_permissions_cluster_role(role['name'])
                                for event in dangerous_permissions:
                                    dangerous_list = [namespace, sa, event['type'], event['name'], event['dangerous_criteria']]
                                    data.append(dangerous_list)
        reporter = Reporter(data, file_name)
        reporter.csv_reporter()


def aws_event_parser(json_event):
    event_list = []

    try:        
        event_list = [
            json_event['awsRegion'],
            json_event['eventName'],
            json_event['eventSource'],
            json_event['eventTime'],
            json_event['sourceIPAddress'],
            json_event['userAgent'],
            json_event['userIdentity']['accessKeyId'],
            json_event['userIdentity']['accountId'],
            json_event['userIdentity']['arn'],
            json_event['userIdentity']['principalId'],
            json_event['userIdentity']['type'],
            json_event['userIdentity']['userName']
        ]
    
    except KeyError as e:
            if e == 'userName':
                event_list = [
                    json_event['awsRegion'],
                    json_event['eventName'],
                    json_event['eventSource'],
                    json_event['eventTime'],
                    json_event['sourceIPAddress'],
                    json_event['userAgent'],
                    json_event['userIdentity']['accessKeyId'],
                    json_event['userIdentity']['accountId'],
                    json_event['userIdentity']['arn'],
                    json_event['userIdentity']['principalId'],
                    json_event['userIdentity']['type'],
                    'None'
                ]

            elif e == 'accessKeyId':
                event_list = [
                    json_event['awsRegion'],
                    json_event['eventName'],
                    json_event['eventSource'],
                    json_event['eventTime'],
                    json_event['sourceIPAddress'],
                    json_event['userAgent'],
                    'None',
                    json_event['userIdentity']['accountId'],
                    json_event['userIdentity']['arn'],
                    json_event['userIdentity']['principalId'],
                    json_event['userIdentity']['type'],
                    json_event['userIdentity']['userName']
                ]
    
    
    return event_list