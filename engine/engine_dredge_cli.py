import pyfiglet
import utils.constants
from utils.argument_parser import dredge_parser
from cloud_status.subcommand_cloud_status import cloud_status_subcommand
from log_retriever.class_engine_log_retriever import log_retriever_from_file
from log_retriever.subcommand_log_retriever import log_retriever_subcommand
from threat_hunting.subcommand_threat_hunting import threat_hunting_subcommand
from incident_response.subcommand_incident_response import incident_response_subcommand


def dredge_cli():
    print(pyfiglet.figlet_format("Dredge"))
    print("Industria Argentina \m/")
    print("Santiago Abastante - sabastante@solidaritylabs.io \n")
    args = dredge_parser().parse_args()
    
    try:
        #CONFIG - Runs using config file
        if args.subcommand == utils.constants.config_cmd:
            log_retriever_from_file(args.file)

        # THREAT HUNTING
        elif args.subcommand == utils.constants.th_cmd:
            threat_hunting_subcommand(args)

        # LOG RETRIEVER
        if args.subcommand == utils.constants.lr_cmd:
            log_retriever_subcommand(args)

        # CLOUD STATUS
        elif args.subcommand == utils.constants.cs_cmd:
            cloud_status_subcommand(args)

        # INCIDENT RESPONSE
        elif args.subcommand == utils.constants.ir_cmd:
            incident_response_subcommand(args)
            
    except KeyboardInterrupt as e:
        print(e)