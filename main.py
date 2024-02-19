import sys
import argparse
sys.path.append('./config_ui')

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

        create_new_folder(".", "system_info")
        collect_system_info()
        create_report()
