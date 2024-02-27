import subprocess
import os
import re
import shutil
import psutil
import json
from datetime import datetime
from tzlocal import get_localzone
import pytz
import socket
import uuid
from config_ui.report_form import report_form
from velociraptor_sever_api import Run_velociraptor_query



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

# def Run_velociraptor_ls(accessor, filePath, verbose=False):
#      # Path to executable of Velociraptor on Windows
#     velociraptor_executable = r".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
#     command = [velociraptor_executable, 'fs', '--accessor', accessor, 'ls', filePath]
#     try:
#         result = subprocess.run(command, shell=True, capture_output=True, text=True)
#         if verbose:
#             print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
#         return result.stdout
#     except subprocess.CalledProcessError as e:
#         print(f"Error: {e.output}")

# def Run_velociraptor_query(query, verbose=False):
#     # Path to executable of Velociraptor on Windows
#     velociraptor_executable = r".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
#     command = [velociraptor_executable, 'query', query, '--format', 'json']
#     try:
#         result = subprocess.run(command, shell=True, capture_output=True, text=True)
#         if verbose:
#             print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
#         return result.stdout
#     except subprocess.CalledProcessError as e:
#         print(f"Error: {e.output}")

def Run_velociraptor_query_csv_format(query, verbose=False):
    # Path to executable of Velociraptor on Windows
    velociraptor_executable = r".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'query', query, '--format', 'csv']
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

def Run_velociraptor_artifacts(artifacts_name,verbose=False):
    # Path to executable of Velociraptor on Windows
    velociraptor_executable = r".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'artifacts collect', artifacts_name, '--format', 'json']
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")



def extract_base_folder(path):
    components = path.split("\\")
    base_folder = components[:-1]
    return "/".join(base_folder)

def collect_evtx_file(outputFolder):
    system_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System\File"
    application_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\File"
    security_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security\File"
    output = Run_velociraptor_ls("reg",system_log_key_path, True)
    system_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    output = Run_velociraptor_ls("reg",application_log_key_path, True)
    application_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    output = Run_velociraptor_ls("reg",security_log_key_path, True)
    security_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    default_log_path = "C:/Windows/system32/winevt/logs"
    sourceFolderList = [default_log_path, extract_base_folder(system_log_path), extract_base_folder(application_log_path), extract_base_folder(security_log_path)]
    uniqueSourceFolderList = list(set(sourceFolderList))
    
    for i in uniqueSourceFolderList:
        query1 = f"SELECT Name, OSPath, Size as RawSize, humanize(bytes=Size) as Size, Mode.String, Mtime FROM glob(globs='{i}/*.evtx') "
        output = Run_velociraptor_query(query1,True)
        list_evtx_files= re.sub(r"\]\[", ",",output)
        parsed = json.loads(list_evtx_files)
        for j in parsed:
            source = re.sub(r"\\", "/", j["OSPath"])
            filename = j["Name"]
            dest = os.path.join(outputFolder,filename)
            query = f"SELECT copy(filename='{source}', accessor='ntfs', dest='{filename}') FROM scope()"
            Run_velociraptor_query(query)
            source = os.path.join(os.getcwd(),filename)
            shutil.move(source, dest)

def collect_system_info():
    data = Run_velociraptor_query("SELECT * From info()")
    # print(data)
    data = eval(data)
    return data

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
            scanID
    )

def get_installed_software():
    data = Run_velociraptor_artifacts("Windows.Sys.Programs")
    data = json.loads(data)
    return data

def get_ip_config_all():
    data = Run_velociraptor_query_csv_format("SELECT Stdout FROM execve(argv=['powershell.exe', '/c', 'ipconfig /all'])")
    return data

data = collect_system_info()
computerName = data[0]["Hostname"]
installTime = str(datetime.utcfromtimestamp(data[0]["BootTime"]))
platform = data[0]["Platform"] + " " + data[0]["PlatformFamily"] + " " + data[0]["PlatformVersion"]
adminRights = data[0]["IsAdmin"]
startTime = get_start_time()
localTimeZone = get_local_TimeZone()
ipAddr = get_ip_address()
runAsUser = get_run_as_user()
scanID = get_scanID()
installed_software = get_installed_software()
ipconfig_all = get_ip_config_all()
# cwd = os.getcwd()
# extractFolder = create_new_folder(cwd, "extract")
# collect_evtx_file(extractFolder)