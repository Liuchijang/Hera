from report_form import report_form

computerName = "computername" 
platform = "windows10" 
installTime = "10/10/2012 12:00:00 GMT+7"
ipAddr = "10.10.101.10" 
runAsUser = "DOMAIN\\Administrator"
adminRights = "Yes" 
startTime = "10/10/2012 12:00:00 GMT+7"
endTime = "10/10/2012 12:00:00 GMT+7"
scanID = "ksj02390jf"
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
