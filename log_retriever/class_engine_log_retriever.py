import os
import json
import requests
import datetime
import yaml
import botocore.exceptions
import time
from modules.class_aws_s3_bucket import S3Bucket
from modules.class_aws_security import GuardDuty, Cloudtrail
from modules.class_aws_cloudwatch_logs import CloudWatchLogGroup
from modules.class_engine_auth import AWSAuth, GCPAuth
from modules.class_github import Github
from modules.class_k8s_cluster import KubernetesCluster
from threat_hunting.class_engine_threat_hunting import ThreatHunting
from google.cloud import logging
from google.api_core.exceptions import InvalidArgument

class LogRetriever:
    def __init__(self, start_date, end_date, destination_path, output_file_name):
        self.start_date = start_date
        self.end_date = end_date
        self.destination_path = destination_path
        self.output_file_name = output_file_name
        self.cloudwatch_events = []
        self.event_history_events = []
        self.guardduty_events = []
        self.github_events = []
        self.gcp_logs = []


    def get_s3_logs(self, session, s3_bucket_name):
        s3_bucket = S3Bucket(session, s3_bucket_name)
        s3_bucket.download_bucket_objects(session, self.start_date, self.end_date, self.destination_path,
                                          self.output_file_name)


    def get_cloudwatch_logs(self, session, log_group_name):
        log_group = CloudWatchLogGroup.constructor(session, log_group_name)
        self.cloudwatch_events.append(log_group.get_cloudwatch_logs(session, self.start_date, self.end_date))


    def get_event_history_logs(self, session):
        cloudtrail = Cloudtrail.constructor(session)
        self.event_history_events.append(cloudtrail.get_event_history_logs(session, self.start_date, self.end_date))


    def get_guardduty_findings(self, session):
        guardduty = GuardDuty.constructor(session)
        self.guardduty_events.append(guardduty.get_guardduty_findings(session))


    def get_github_logs(self, github):
        github_events = []
        per_page = 100
        if github.enterprise:
            url = f'https://api.github.com/enterprises/{github.enterprise}/audit-log?include=all&per_page={per_page}'
            while True:
                response = requests.get(url, headers=github.headers)
                if response.status_code == 200:
                    for event in response.json():

                        event['@timestamp'] = datetime.datetime.utcfromtimestamp(
                            event['@timestamp'] / 1e3).isoformat() + 'Z'
                        try:
                            event['created_at'] = datetime.datetime.utcfromtimestamp(
                                event['created_at'] / 1e3).isoformat() + 'Z'
                        except KeyError as e:
                            pass

                        if self.start_date <= event['@timestamp'][0:10] <= self.end_date:
                            github_events.append(event)
                            print(event)
                            print()
                            time.sleep(1)
                    if "next" in response.links:
                        url = response.links["next"]["url"]
                    else:
                        break
                else:
                    print(f'Error: {response.status_code} - {response.json()["message"]}')

        if github.organization:
            url = f'https://api.github.com/orgs/{github.organization}/audit-log?include=all&per_page={per_page}'

            while True:
                response = requests.get(url, headers=github.headers)
                if response.status_code == 200:
                    for event in response.json():

                        event['@timestamp'] = datetime.datetime.utcfromtimestamp(
                            event['@timestamp'] / 1e3).isoformat() + 'Z'
                        try:
                            event['created_at'] = datetime.datetime.utcfromtimestamp(
                                event['created_at'] / 1e3).isoformat() + 'Z'
                        except KeyError as e:
                            pass

                        if self.start_date <= event['@timestamp'][0:10] <= self.end_date:
                            github_events.append(event)
                            print(event)
                            print()
                            time.sleep(1)
                    if "next" in response.links:
                        url = response.links["next"]["url"]
                    else:
                        break
                else:
                    print(f'Error: {response.status_code} - {response.json()["message"]}')

            self.github_events = github_events


    def json_reporter(self):
        currentPath = os.getcwd()
        try:
            os.mkdir(self.destination_path)
            os.chdir(self.destination_path)
        except FileExistsError as e:
            os.chdir(self.destination_path)

        if self.event_history_events:
            os.chdir(currentPath)
            os.chdir(self.destination_path)
            final_output = f"dredge_event_history_logs_{datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')}.json"

            jsonFile = open(final_output, "w")
            for event in self.event_history_events:
                try:
                    str_event = json.dumps(event, indent=4, sort_keys=True, default=str)
                    jsonFile.write(str_event)
                except TypeError as e:
                    print(e)

            jsonFile.close()
            os.chdir(currentPath)
            print(f'- Created {final_output} File')


        if self.guardduty_events:
            os.chdir(currentPath)
            os.chdir(self.destination_path)
            final_output = f"dredge_guardduty_events_{datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')}.json"

            jsonFile = open(final_output, "w")
            for event in self.guardduty_events:
                try:
                    str_event = json.dumps(event, indent=4, sort_keys=True, default=str)
                    jsonFile.write(str_event)
                except TypeError as e:
                    print(e)

            jsonFile.close()
            os.chdir(currentPath)
            print(f'- Created {final_output} File')

        if self.cloudwatch_events:
            os.chdir(currentPath)
            os.chdir(self.destination_path)
            final_output = f"dredge_cloudwatch_logs_{datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')}.json"

            jsonFile = open(final_output, "w")
            for event in self.cloudwatch_events:
                try:
                    str_event = json.dumps(event, indent=4, sort_keys=True, default=str)
                    jsonFile.write(str_event)
                except TypeError as e:
                    print(e)

            jsonFile.close()
            os.chdir(currentPath)
            print(f'- Created {final_output} File')

        if self.github_events:
            os.chdir(currentPath)
            os.chdir(self.destination_path)
            final_output = f"dredge_github_logs_{datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')}.json"

            jsonFile = open(final_output, "w")
            for event in self.github_events:
                try:
                    str_event = json.dumps(event, indent=4, sort_keys=True, default=str)
                    jsonFile.write(str_event)
                except TypeError as e:
                    print(e)

            jsonFile.close()
            os.chdir(currentPath)
            print(f'- Created {final_output} File')

        if self.gcp_logs:
            os.chdir(currentPath)
            os.chdir(self.destination_path)
            final_output = f"dredge_gcp_logs_{datetime.datetime.today().strftime('%Y-%m-%d-%H:%M:%S')}.json"

            jsonFile = open(final_output, "w")
            for event in self.gcp_logs:
                print(event)
                print()
                try:
                    str_event = json.dumps(event, indent=4, sort_keys=True, default=str)
                    jsonFile.write(str_event)
                except TypeError as e:
                    print(e)

            jsonFile.close()
            os.chdir(currentPath)
            print(f'- Created {final_output} File')


    def get_k8s_logs(self, namespace, pod, config):
        try:
            k8s = KubernetesCluster(config)
            logs = k8s.get_pod_logs(namespace, pod)
            self.k8s_logs = logs
            return logs
        except Exception as e:
            print(e)
            exit(0)


    def get_k8s_namespace_events(self, namespace, config):
        k8s = KubernetesCluster(config)
        namespace_events = k8s.get_namespace_events(namespace)
        return namespace_events
    

    def get_gcp_api_logs(self, cred_file, start_date, end_date):
        gcp = GCPAuth(cred_file)
        if start_date:
            start_datetime_str = f'{start_date}T00:00:00Z'
            end_datetime_str = f'{end_date}T23:59:59Z'
            filter_string = f'timestamp >= "{start_datetime_str}" AND timestamp <= "{end_datetime_str}"'
        else:
            filter_string = None

        # List all logs in the specified project
        try:
            self.gcp_logs = gcp.client.list_entries(filter_=filter_string) 
        except InvalidArgument as e:
            print(e, 'Dates are required in the following time format: 2023-09-30 (YYYY-MM-DD)')


def log_retriever_from_file(config_file):
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)
    try:
        os.mkdir(config['configs']['destination_folder'])
    except FileExistsError as e:
        pass

    # LOG RETRIEVER
    log_retriever = LogRetriever(config['configs']['start_date'], config['configs']['end_date'],
                                 config['configs']['destination_folder'], config['configs']['output_file'])

    print(f"Setting up configurations...")
    print()
    time.sleep(2)
    print(f"Start Date: {config['configs']['start_date']} \n"
          f"End Date: {config['configs']['end_date']} \n"
          f"Destination Folder: {config['configs']['destination_folder']}\n"
          f"AWS Logs: {config['aws_configs']['enabled']} \n"
          f"GCP Logs: {config['gcp_configs']['enabled']} \n"
          f"Github Logs: {config['github_configs']['enabled']} \n")
    print("------------------------------------------------------------------")
    time.sleep(2)

    if config['aws_configs']['enabled']:
        for profile in config['aws_configs']['profiles']:
            session = AWSAuth(profile, config['aws_configs']['profile_region']).session
            if config['aws_configs']['lb']['enabled']:
                print()
                print('[LoaBalancer]')
                for bucket in config['aws_configs']['lb']['buckets']:
                    print(f'- Starting to retrieve logs from "{bucket}" S3 bucket')
                    try:
                        log_retriever.get_s3_logs(session, bucket)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

            if config['aws_configs']['waf']['enabled']:
                print()
                print(f'[WAF]')
                for bucket in config['aws_configs']['waf']['buckets']:

                    print(f'- Starting to retrieve logs from "{bucket}" S3 bucket')
                    try:
                        log_retriever.get_s3_logs(session, bucket)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

            if config['aws_configs']['vpc_flow_logs']['enabled']:
                print()
                print(f'[VPC Flow Logs]')
                for bucket in config['aws_configs']['vpc_flow_logs']['buckets']:
                    print(f'- Starting to retrieve logs from "{bucket}" S3 bucket')
                    try:
                        log_retriever.get_s3_logs(session, bucket)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

            if config['aws_configs']['cloudtrail']['enabled']:
                print()
                print(f'[Cloudtrail]')
                for bucket in config['aws_configs']['cloudtrail']['buckets']:
                    print(f'- Starting to retrieve logs from "{bucket}" S3 bucket')
                    try:
                        log_retriever.get_s3_logs(session, bucket)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

            if config['aws_configs']['custom']['enabled']:
                print()
                print(f'[Custom Buckets]')
                for bucket in config['aws_configs']['cloudtrail']['buckets']:
                    print(f'- Starting to retrieve logs from "{bucket}" S3 bucket')
                    try:
                        log_retriever.get_s3_logs(session, bucket)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

            if config['aws_configs']['event_history']['enabled']:
                print()
                print(f'[Event History]')
                print(f'- Starting to retrieve logs from "Event History"')
                try:
                    log_retriever.get_event_history_logs(session)
                except botocore.exceptions.ParamValidationError as e:
                    print(e)

            if config['aws_configs']['guardduty']['enabled']:
                print()
                print(f'[Guardduty]')
                print(f'- Starting to retrieve logs from "Guardduty"')
                try:
                    log_retriever.get_guardduty_findings(session)
                except botocore.exceptions.ParamValidationError as e:
                    print(e)

            if config['aws_configs']['cloudwatch_logs']['enabled']:
                print()
                print(f"[Cloudwatch Logs]")
                for log_group in config['aws_configs']['cloudwatch_logs']['log_group_names']:
                    print(f'- Starting to retrieve logs from "{log_group}" Log Group')
                    try:
                        log_retriever.get_cloudwatch_logs(session, log_group)
                    except botocore.exceptions.ParamValidationError as e:
                        print(e)

    if config['github_configs']['enabled']:
        print()
        print('[Github Logs]')
        for org in config['github_configs']['org_name']:
            print(f'- Starting to retrieve logs from "{org}" Github Organization')
            github = Github(config['github_configs']['access_token'], org)
            log_retriever.get_github_logs(github)

        for ent in config['github_configs']['ent_name']:
            github = Github(config['github_configs']['access_token'], None, ent)
            log_retriever.get_github_logs(github)

    if config['gcp_configs']['enabled']:
        print()
        print('[GCP Logs]')
        for project in config['gcp_configs']['cred_files']:
            log_retriever.get_gcp_api_logs(project, config['configs']['start_date'], config['configs']['end_date'])

    else:
        print('Nothing to do :(')
        exit(0)
    print()
    print(f'- Writing logs into "{log_retriever.destination_path} folder"')
    log_retriever.json_reporter()
    print()
