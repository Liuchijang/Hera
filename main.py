import sys
import argparse
sys.path.append('./config_ui')

import os
from config_ui.report_form import report_form
from collection import *
# from collection import (
#         computerName, 
#         platform, 
#         installTime,
#         localTimeZone, 
#         ipAddr, 
#         runAsUser, 
#         adminRights, 
#         startTime, 
#         endTime,
#         scanID,
#         systeminfor_folder
#         )

if __name__ == "__main__":

        parser = argparse.ArgumentParser(description="Hera is not thor")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
        args = parser.parse_args()
        print(args)

        os.makedirs(systeminfor_folder, exist_ok=True)
        collect_system_info(message_list, command_list, file_list, args.verbose)
        report_form( 
                computerName, 
                platform, 
                installTime,
                localTimeZone, 
                ipAddr, 
                runAsUser, 
                adminRights, 
                startTime, 
                endTime,
                scanID
        )
