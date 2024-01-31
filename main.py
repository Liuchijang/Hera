from report_form import report_form
from collection import (
        computerName, 
        platform, 
        installTime, 
        ipAddr, 
        runAsUser, 
        adminRights, 
        startTime, 
        endTime,
        scanID
        )

if __name__ == "__main__":
        report_form( 
                computerName, 
                platform, 
                installTime, 
                ipAddr, 
                runAsUser, 
                adminRights, 
                startTime, 
                endTime,
                scanID
        )
