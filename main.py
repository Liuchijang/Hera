import os
from report_form import report_form
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
        os.makedirs(systeminfor_folder, exist_ok=True)
        collect_system_info(message_list, command_list, file_list)
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
