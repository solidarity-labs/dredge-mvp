import json
import botocore
import time
from pprint import pprint
from time import sleep

class GuardDuty:
    def __init__(self, enabled, detectors, current_region):
        self.enabled = enabled
        self.detector_ids = detectors
        self.region = current_region

    @classmethod
    def constructor(cls, session):
        guardduty_client = session.client('guardduty')
        current_region = session.region_name
        detectors = guardduty_client.list_detectors()
        if detectors['DetectorIds']:
            enabled = True
        else:
            enabled = False

        return cls(enabled, detectors['DetectorIds'], current_region)

    def get_guardduty_findings(self, session):
        first = True
        next_token = ''
        guardduty_events = []

        client = session.client('guardduty')
        try:

            for detector in self.detector_ids:
                while True:
                    if first:
                        findings = client.list_findings(DetectorId=f'{detector}')
                        next_token = findings['NextToken']
                        events_findings = []
                        for i in findings['FindingIds']:
                            finding = []
                            finding.append(i)

                            try:
                                events = client.get_findings(DetectorId=f'{detector}', FindingIds=finding)
                                for finding in events['Findings']:
                                    pprint(finding)
                                    sleep(1)                                
                                
                                guardduty_events.append(events)

                            except ValueError as e:
                                continue

                            except TypeError as e:
                                continue

                            except KeyboardInterrupt as e:
                                exit(0)

                    else:
                        findings = client.list_findings(DetectorId=f'{detector}', NextToken=next_token)
                        next_token = findings['NextToken']
                        for i in findings['FindingIds']:
                            finding = []
                            finding.append(i)

                            try:
                                events = client.get_findings(DetectorId=f'{detector}', FindingIds=finding)
                                guardduty_events.append(events)
                                print(events)
                                print()

                            except ValueError as e:
                                continue

                    first = False
                    if next_token == '':
                        break

        except botocore.exceptions.EndpointConnectionError as e:
            print(e)

        return guardduty_events


class Cloudtrail:
    def __init__(self, enabled, region, trails):
        self.enabled = enabled
        self.region = region or None
        self.trails = trails or None

    @classmethod
    def constructor(cls, session):
        cloudtrail_client = session.client('cloudtrail')
        response = cloudtrail_client.describe_trails()
        current_region = session.region_name

        cloudtrail_trails = []

        trails = response.get('trailList', [])
        if trails:
            enabled = True
            for trail in trails:
                cloudtrail_trails.append(CloudtrailTrail(trail['Name'], trail['S3BucketName'], trail['LogFileValidationEnabled'],
                                                         trail['IsMultiRegionTrail'], trail['IsOrganizationTrail']))

        else:
            enabled = False

        return cls(enabled, current_region, cloudtrail_trails)

    def get_event_history_logs(cls, session, start_date, end_date):
        first = True
        nextToken = ''
        event_history_events = []
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
                        print(json_cloudtrail_event)
                    
                        print()
                        event_history_events.append(json_cloudtrail_event)

                except KeyError as e:
                    print(e)
                    continue



                nextToken = str(cloudtrail_response['NextToken'])
                first = False
            except KeyError as e:
                break

            except KeyboardInterrupt as e:
                print(e)
                exit(0)
                    
        time.sleep(2)
        return event_history_events


class CloudtrailTrail:
    def __init__(self, trail_name, s3_bucket_name, log_file_validation, multi_region_trail,  organizational_trail):
        self.trail_name = trail_name
        self.s3_bucket_name = s3_bucket_name
        self.log_file_validation = log_file_validation
        self.multi_region_trail = multi_region_trail
        self.organizational_trail = organizational_trail

