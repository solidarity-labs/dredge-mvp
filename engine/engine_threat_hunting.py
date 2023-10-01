import re
import requests
import csv
import time
import json
import socket
import os
from tabulate import tabulate
from tqdm import tqdm
from engine.vars import th_csv_file_name, dangerous_api_calls, th_json_file_name

def vt_file_scan(file_name, vt_key):
    ip_address = ip_retriever(file_name)
    results = []
    headers = ['IP', 'ASN', 'ASN_NAME', 'COUNTRY', 'IS_BAD']
    results.append(headers)

    print(f'Processing {len(ip_address)} IPs')   
    for ip in  tqdm(ip_address, desc="Processing", unit="item"):
        results.append(vt_ip_scan(ip, vt_key))

    table = tabulate(results, headers="firstrow", tablefmt="fancy_grid")
    print()
    print(table)
    vt_reporter(results)


def vt_ip_scan(ip_address, vt_key):
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
            parsed_data = vt_parser(data)
            return parsed_data

        else:
            print(f"Error: {response.status_code} - {response.text}")

    except Exception as e:    
        print(f"Error: {e}")


def vt_parser(data):
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


def ip_retriever(file: str) -> list:
    '''
    :param eventHistoryFile: Text file with the json output, but it can get ips from whatever text you want
    :return: list of unique ips
    '''
    ips = []
    try:
        with open(f'{file}', 'r') as file:
            contents = file.read()
            #ip_list = re.findall(r'(\d[0-9]{1,3}\.\d[0-9]{1,3}\.\d[0-9]{1,3}\.\d[0-9]{1,3})', contents)
            ip_list = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', contents)
            sorted_ip_list = sorted(set(ip_list))
            
            for ip in sorted_ip_list:
                ips.append(ip)
                
            return ips

    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        pass


def vt_reporter(data):
    # Open the CSV file in write mode
    with open(th_csv_file_name, mode='w', newline='') as file:
        # Create a CSV writer object
        writer = csv.writer(file)

        # Write the data to the CSV file
        writer.writerows(data)

    print(f'CSV file "{th_csv_file_name}" has been created successfully.')


def get_event_history_alerts(session, start_date, end_date, ips=[]):
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
                    try:
                        json_cloudtrail_event['responseElements']['credentials'] = []
                    except KeyError as e:
                        continue

                    except TypeError as e:
                        continue

                    if ips:
                        if json_cloudtrail_event['sourceIPAddress'] in ips:
                            json_cloudtrail_event['DANGEROUS IOC'] = json_cloudtrail_event['sourceIPAddress']
                            print(json_cloudtrail_event)
                            print()
                            event_history_events.append(json_cloudtrail_event)


                    else:
                        if json_cloudtrail_event['eventName'] in dangerous_api_calls:
                            json_cloudtrail_event['DANGEROUS API CALL'] = True
                            print(json_cloudtrail_event)
                            print()
                            event_history_events.append(json_cloudtrail_event)


            except KeyError as e:
                continue

            nextToken = str(cloudtrail_response['NextToken'])
            first = False
        except KeyError as e:
            break

    time.sleep(2)
    json_reporter(event_history_events, th_json_file_name)
    return event_history_events


def json_reporter(data_dict, th_json_file_name):
    try:
        # Create the file path in the current directory
        file_path = os.path.join(os.getcwd(), th_json_file_name)

        # Write the data to the JSON file
        with open(file_path, 'w') as json_file:
            json.dump(data_dict, json_file, indent=4)

        print(f"JSON file '{th_json_file_name}.json' created in the current directory.")
    except Exception as e:
        print(f"Error creating JSON file: {str(e)}")