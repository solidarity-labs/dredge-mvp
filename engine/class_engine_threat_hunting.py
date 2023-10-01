import re
import whois
import shodan
import requests
import json
import time
from pprint import pprint

dangerous_api_calls = [
    # Amazon S3
    'CreateBucket',
    'DeleteBucket',
    'PutBucketPolicy',
    'DeleteBucketPolicy',
    'PutObject',
    'DeleteObject',

    # Amazon EC2
    'TerminateInstances',
    'StopInstances',
    'StartInstances',
    'RebootInstances',
    'CreateImage',
    'DeleteSnapshot',

    # AWS IAM
    'CreateUser',
    'DeleteUser',
    'CreateAccessKey',
    'DeleteAccessKey',
    'CreateLoginProfile',
    'DeleteLoginProfile',
    'CreateGroup',
    'DeleteGroup',
    'CreatePolicy',
    'DeletePolicy',
    'AttachUserPolicy',
    'AttachGroupPolicy',
    'AttachRolePolicy',
    'DetachUserPolicy',
    'DetachGroupPolicy',
    'DetachRolePolicy',

    # Amazon RDS
    'DeleteDBInstance',
    'DeleteDBSnapshot',
    'DeleteDBCluster',
    'DeleteDBClusterSnapshot',

    # AWS Lambda
    'DeleteFunction',
    'DeleteLayerVersion',
    'UpdateFunctionCode',
    'UpdateFunctionConfiguration',

    # Amazon DynamoDB
    'DeleteTable',
    'DeleteItem',
    'UpdateItem',
    'PutItem',

    # AWS CloudFormation
    'DeleteStack',
    'CreateStack',
    'UpdateStack',
    'CreateChangeSet',
    'DeleteChangeSet',

    # Amazon SQS
    'DeleteQueue',
    'SendMessage',
    'DeleteMessage',

    # Amazon SNS
    'DeleteTopic',
    'Publish',
    'Subscribe',

    # AWS Secrets Manager
    'DeleteSecret',
    'PutSecretValue',
    'RestoreSecret',

    # Amazon EC2 Auto Scaling
    'DeleteAutoScalingGroup',
    'UpdateAutoScalingGroup',

    # AWS Elastic Beanstalk
    'DeleteApplication',
    'DeleteEnvironment',

    # AWS Identity and Access Management
    'DeleteVirtualMFADevice',
    'DeactivateMFADevice'
]


class ThreatHunting:
    def __init__(self):
        self.ips = []
        self.shodan_enriched_ips = []
        self.whois_enriched_ips = []

    def ip_retriever(self, file: str) -> list:
        '''
        :param eventHistoryFile: Text file with the json output, but it can get ips from whatever text you want
        :return: list of unique ips
        '''
        try:
            with open(f'{file}', 'r') as file:
                contents = file.read()
                ip_list = re.findall(r'(\d[0-9]{1,3}\.\d[0-9]{1,3}\.\d[0-9]{1,3}\.\d[0-9]{1,3})', contents)
                sorted_ip_list = sorted(set(ip_list))
                for ip in sorted_ip_list:
                    self.ips.append(ip)
                return self.ips

        except FileNotFoundError:
            print("File not found.")
        except Exception as e:
            pass


    def whois_enrichment(self, ip):
        whois_ip = whois.whois(ip)
        if whois_ip['domain_name']:
            whois_ip['ip_address'] = ip
            self.whois_enriched_ips.append(whois_ip)
            print(whois_ip)

        return self.whois_enriched_ips

    def reporter(self):
        #self.destination_path = destination_path
        #self.output_file_name = output_file_name
        pass


def shodan_enrichment(ip, api_key):
    api = shodan.Shodan(api_key)
    try:
        # Lookup the IP address information
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        print(f'- Error: {e}')


def vt_analyze_file(vt_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    # Make a POST request to VirusTotal API
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            params = {'apikey': vt_key}
            response = requests.post(url, files=files, params=params)
            # Check the response status code
            if response.status_code == 200:
                json_response = response.json()

                # Print the response from VirusTotal
                file_hash = json_response['sha1']
                print(file_hash)
                # Check the response code to determine if the analysis is queued or already finished
                response_code = json_response.get('response_code', -1)
                while True:
                    if response_code == 1:
                        print('File analysis completed.')
                        break
                    elif response_code == -2:
                        print('File analysis is still queued for scanning. Try again later.')
                    else:
                        print('Error occurred during file analysis.')
            else:
                print(f'Request failed with status code {response.status_code}')
    except IOError as e:
        print(f'Error opening file: {e}')

    # Make a GET request to VirusTotal API
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': vt_key, 'resource': file_hash}
    response = requests.get(url, params=params)
    # Check the response status code
    if response.status_code == 200:
        json_response = response.json()

        # Print the response from VirusTotal
        print(f"Message: {json_response['verbose_msg']}")
        print(f"Total: {json_response['total']}")
        print(f"Positives: {json_response['positives']}")
        print(f"SHA256: {json_response['sha256']}")
        print(f"MD5: {json_response['md5']}")

    else:
        print(f'Request failed with status code {response.status_code}')


def vt_analyze_ip(vt_key, ip_address):
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


def vt_analyze_domain(vt_key, domain):
    url = f'https://www.virustotal.com/vtapi/v2/domain/report'

    # Make a GET request to VirusTotal API
    params = {'apikey': vt_key, 'domain': domain}
    response = requests.get(url, params=params)

    # Check the response status code
    if response.status_code == 200:
        json_response = response.json()
        # Check if the domain has been analyzed previously
        if 'detected_urls' in json_response:
            # Print the detected malicious URLs associated with the domain
            print('Detected Malicious URLs:')
            for url in json_response['detected_urls']:
                print(f'URL: {url["url"]}')
                print(f'Positives: {url["positives"]}')
                print(f'Total: {url["total"]}\n')
        else:
            print('Domain has not been analyzed previously.')
        print(f'Bitdefender Category: {json_response["BitDefender category"]}')
        print(f'Sophos Category: {json_response["Sophos category"]}')

    else:
        print(f'Request failed with status code {response.status_code}')


def vt_analyze_hash(vt_key, hash):
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


def get_event_history_alerts(session, start_date, end_date, ips=[]):
    first = True
    nextToken = ''
    event_history_events = []
    print('- Now we are going to try to find and show dangerous API Calls: ')
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

                    try:
                        json_cloudtrail_event['responseElements']['credentials'] = []
                    except KeyError as e:
                        continue

                    except TypeError as e:
                        continue

                    if ips:
                        if json_cloudtrail_event['sourceIPAddress'] in ips:
                            json_cloudtrail_event['DANGEROUS IOC'] = json_cloudtrail_event['sourceIPAddress']
                            pprint(json_cloudtrail_event)
                            print()

                    else:
                        if json_cloudtrail_event['eventName'] in dangerous_api_calls:
                            json_cloudtrail_event['DANGER API CALL'] = True
                            pprint(json_cloudtrail_event)
                            print()


            except KeyError as e:
                continue

            nextToken = str(cloudtrail_response['NextToken'])
            first = False
        except KeyError as e:
            break
    time.sleep(2)
    return event_history_events