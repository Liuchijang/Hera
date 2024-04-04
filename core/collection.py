import os
import re
import shutil
import psutil
from datetime import datetime
from tzlocal import get_localzone
import pytz
import socket
import uuid
from config.config_ui.report_form import report_form
from core.velociraptor_sever_api import Run_velociraptor_query
from core.matching import malware_instances_res

computerName = ""
platform = ""
installTime = ""
localTimeZone = ""
ipAddr = ""
runAsUser = ""
adminRights = ""
startTime = ""
scanID = ""

def get_local_TimeZone():
    now = datetime.now()
    timezone_name = str(get_localzone())
    timezone = pytz.timezone(timezone_name)
    gmt_offset = int(timezone.utcoffset(now).total_seconds() // 3600)
    return timezone_name + " GMT+" + str(gmt_offset)

def get_ip_address():
    return socket.gethostbyname(socket.gethostname())

def get_run_as_user():
    return psutil.Process().username()

def get_start_time():
    return datetime.fromtimestamp(psutil.Process().create_time()).strftime("%Y-%m-%d %H:%M:%S.%f")

def create_new_folder(baseFolder, newFoldername):
    folderPath = os.path.join(baseFolder,newFoldername)
    os.makedirs(folderPath,exist_ok=True)
    return folderPath
    
def create_new_file(filename, filepath, data):
    newfile = os.path.join(filepath,filename)
    try:
        with open(newfile,"w") as file:
            if isinstance(data, str):
                file.write(data)
            else:
                # If data is a list or tuple, write each element on a new line
                for line in data:
                    file.write(line + "\n")
            print(f"File '{newfile}' created successfully!")
    except IOError as e:
        print(f"Error creating file: {e}")

def extract_base_folder(path):
    components = path.split("\\")
    base_folder = components[:-1]
    return "/".join(base_folder)

def extract_Windows_base_folder(path):
    components = path.split("\\")
    base_folder = components[:-1]
    return "\\".join(base_folder)

def collect_necessary_evtx(outputFolder, verbose=False):
    system_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/System/File"
    application_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/Application/File"
    security_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/Security/File"
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{system_log_key_path}', accessor='reg') ")   
    system_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{application_log_key_path}', accessor='reg') ") 
    application_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{security_log_key_path}', accessor='reg') ") 
    security_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    default_log_path = "C:/Windows/system32/winevt/logs"
    sourceFolderList = [default_log_path, extract_base_folder(system_log_path), extract_base_folder(application_log_path), extract_base_folder(security_log_path)]
    uniqueSourceFolderList = list(set(sourceFolderList))
    list_files = ['Security.evtx',
                  'System.evtx',
                  'Microsoft-Windows-Sysmon%4Operational.evtx',
                  'Microsoft-Windows-PowerShell%4Operational.evtx',
                  'Microsoft-Windows-Windows Defender%4Operational.evtx',
                  'Microsoft-Windows-SMBServer%4Operational.evtx',
                  'Microsoft-Windows-SmbClient%4Connectivity.evtx',
                  'Microsoft-Windows-Bits-Client%4Operational.evtx',
                  'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
                  'Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx',
                  'Microsoft-Windows-WMI-Activity%4Operational.evtx',
                  'Microsoft-Windows-TaskScheduler%4Operational.evtx']
    for i in uniqueSourceFolderList:
        for k in list_files:
            query1 = f"SELECT Name, OSPath, Size as RawSize, humanize(bytes=Size) as Size, Mode.String, Mtime FROM glob(globs='{i}/{k}') "
            output = Run_velociraptor_query(query1)
            list_evtx_files= re.sub(r"\]\[", ",",output)
            parsed = eval(list_evtx_files)
            for j in parsed:
                source = re.sub(r"\\", "/", j["OSPath"])
                filename = j["Name"]
                dest = os.path.join(outputFolder,filename)
                query = f"SELECT copy(filename='{source}', accessor='ntfs', dest='{filename}') FROM scope()"
                Run_velociraptor_query(query)
                if verbose: print(f"Collect {source} successfully, saved at {dest}")
                source = os.path.join(os.getcwd(),filename)
                shutil.move(source, dest)

def collect_evtx_file(outputFolder, verbose=False):
    print("+"*50 + "\nCollecting all evtx files...")
    system_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/System/File"
    application_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/Application/File"
    security_log_key_path = "HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/Security/File"
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{system_log_key_path}', accessor='reg') ")   
    system_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{application_log_key_path}', accessor='reg') ") 
    application_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    output = Run_velociraptor_query(f"SELECT * FROM glob(globs='{security_log_key_path}', accessor='reg') ") 
    security_log_path = os.path.expandvars(eval(output)[0]["Data"]["value"].lower())
    default_log_path = "C:/Windows/system32/winevt/logs"
    sourceFolderList = [default_log_path, extract_base_folder(system_log_path), extract_base_folder(application_log_path), extract_base_folder(security_log_path)]
    uniqueSourceFolderList = list(set(sourceFolderList))
    
    for i in uniqueSourceFolderList:
        query1 = f"SELECT Name, OSPath, Size as RawSize, humanize(bytes=Size) as Size, Mode.String, Mtime FROM glob(globs='{i}/*.evtx') "
        output = Run_velociraptor_query(query1)
        list_evtx_files= re.sub(r"\]\[", ",",output)
        parsed = eval(list_evtx_files)
        for j in parsed:
            source = re.sub(r"\\", "/", j["OSPath"])
            filename = j["Name"]
            dest = os.path.join(outputFolder,filename)
            query = f"SELECT copy(filename='{source}', accessor='ntfs', dest='{filename}') FROM scope()"
            Run_velociraptor_query(query)
            if verbose: print(f"Collect {source} successfully, saved at {dest}")
            source = os.path.join(os.getcwd(),filename)
            shutil.move(source, dest)
    print(f"Collecting completed, saved at folder {outputFolder}")

def collect_OBJECT_DATA(outputFolder,verbose=False):
    print("+"*50 + "\nCollecting WMI Repository...")
    query = "SELECT Name, OSPath, Size as RawSize, humanize(bytes=Size) as Size, Mode.String, Mtime FROM glob(globs='C:/Windows/system32/wbem/Repository/**/OBJECTS.DATA',accessor='ntfs')"
    output = Run_velociraptor_query(query)
    parsed = eval(output)
    for i in parsed:
        source = re.sub(r"\\", "/", i["OSPath"])
        filename = i["Name"]
        dest = os.path.join(outputFolder,filename)
        query1 = f"SELECT copy(filename='{source}', accessor='ntfs', dest='{filename}') FROM scope()"
        Run_velociraptor_query(query1)
        if verbose: print(f"Collect {source} successfully, saved at {dest}")
        source = os.path.join(os.getcwd(),filename)
        shutil.move(source, dest)
    print(f"Collecting completed")

def collect_system_info():
    data = Run_velociraptor_query("SELECT * From info()")
    # print(data)
    data = eval(data)
    global computerName 
    global platform
    global installTime
    global localTimeZone
    global ipAddr 
    global runAsUser
    global adminRights
    global startTime
    global scanID
    computerName = data[0]["Hostname"]
    installTime = str(datetime.utcfromtimestamp(data[0]["BootTime"]))
    platform = data[0]["Platform"] + " " + data[0]["PlatformFamily"] + " " + data[0]["PlatformVersion"]
    adminRights = data[0]["IsAdmin"]
    startTime = get_start_time()
    localTimeZone = get_local_TimeZone()
    ipAddr = get_ip_address()
    runAsUser = get_run_as_user()
    scanID = get_scanID()

def get_scanID():   
    return computerName + "_" + str(uuid.uuid4())

def create_report():
    endTime = datetime.now()
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
                scanID,
                malware_instances_res
        )


if __name__ == "__main__":
    collect_system_info()
   


