import botocore
import boto3
import utils.constants
from utils.utils import args_date_validator
from threat_hunting.class_engine_threat_hunting import ThreatHunting
from tabulate import tabulate
from modules.class_k8s_cluster import KubernetesCluster


def threat_hunting_subcommand(args):
    threat_hunting = ThreatHunting()
    
    # VIRUSTOTAL HUNTING
    if args.th_subcommand == utils.constants.th_vt_subparser:
        
        if args.ip:
            results = []
            headers = ['IP', 'ASN', 'ASN_NAME', 'COUNTRY', 'IS_BAD']
            results.append(headers)
            vt_result = threat_hunting.vt_ip_scan(args.ip, args.key)
            results.append(vt_result)
            table = tabulate(results, headers="firstrow", tablefmt="fancy_grid")
            print(table)
            
        elif args.file:
            threat_hunting.vt_analyze_file(args.file, args.key)

    # IP HUNTING
    if args.th_subcommand == utils.constants.th_ip_subparser:
        ips = threat_hunting.ip_retriever(args.file)
        print(ips)

    # WHOIS HUNTING
    if args.th_subcommand == utils.constants.th_whois_subparser:
        if args.file:
            ips = threat_hunting.ip_retriever(args.file)
            print(ips)
            for ip in ips:
                ip_result = threat_hunting.whois_enrichment(ip)
                print(ip_result)
                print()

        elif args.target:
            result = threat_hunting.whois_enrichment(args.target)
            print(result)

    # SHODAN HUNTING
    if args.th_subcommand == utils.constants.th_shodan_subparser:
        if args.ip:
            result = threat_hunting.shodan_enrichment(args.ip, args.key)
            print(result)
        
        elif args.file:
            ips = threat_hunting.ip_retriever(args.file)
            for ip in ips:
                result = threat_hunting.shodan_enrichment(ip, args.key)
                print(result)
                print()
            
    # K8S
    elif args.th_subcommand == utils.constants.th_k8s_subparser:
            threat_hunting.detect_k8s_dangerous_permissions(args)

    # AWS HUNTING
    elif args.th_subcommand == utils.constants.th_aws_subparser:
        start_date, end_date = args_date_validator(args)
        try:
            session = boto3.session.Session(profile_name=f'{args.profile}',
                                        region_name=f'{args.region}')
        except botocore.exceptions.ProfileNotFound as e:
            raise(e)

        threat_hunting.get_event_history_alerts(session, start_date, end_date, args)


