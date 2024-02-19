import sys
sys.path.append('./config_ui')

import os
import subprocess
import ctypes
import import subprocess
import os
import re
import shutil
import json

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

def Run_velociraptor_ls(accessor, filePath, verbose=False):
     # Path to executable of Velociraptor on Windows
    velociraptor_executable = r"velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'fs', '--accessor', accessor, 'ls', filePath]
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

def Run_velociraptor_query(query, verbose=False):
    # Path to executable of Velociraptor on Windows
    velociraptor_executable = r".\\velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'query', query, '--format', 'json']
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

cwd = os.getcwd()
extractFolder = create_new_folder(cwd, "extract")
collect_evtx_file(extractFolder)
import psutil
import platform
import datetime
import random
import string
import re
from datetime import datetime
import pytz
import atexit
from tzlocal import get_localzone
from config_ui.process_bar import process_bar

def get_computer_name():
    return socket.gethostname()

def get_platform():
    return platform.platform()

def get_install_time():
    return datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

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

def has_admin_rights():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def get_start_time():
    return datetime.fromtimestamp(psutil.Process().create_time()).strftime("%Y-%m-%d %H:%M:%S")

def get_end_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_scanID(seed=hash(get_start_time()) & 0xFFFFFFFFFFFFFFFF):
    random.seed(seed)
    characters = string.ascii_letters + string.digits  # Bảng chữ cái và số
    random_string = ''.join(random.choice(characters) for _ in range(10))    
    return get_computer_name() + "_" + random_string

# @process_bar
def create_sysinfo_file(command, file_name, verbose):
    try:
        # print(message)
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, text=True)
        if verbose: print(result)
        with open(os.path.join(systeminfor_folder, file_name), 'w') as file:
            file.write(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing {command}: {e}")

def collect_system_info(message_list, command_list, file_list, verbose):
    for message, command, file in zip(message_list, command_list, file_list):
        print(message)       
        create_sysinfo_file(command, file, verbose)

message_list = [
    "Collecting installed softwares...",
    "Collecting ip config...",
    "Collecting sevices...",
    "Collecting system information..."
]

command_list = [
    "powershell \"Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String -Width 4096\"",
    "ipconfig /all",
    "powershell \"Get-Service | Sort-Object Status -Descending | Format-Table -AutoSize\"",
    "systeminfo"
]

file_list = [
    "installed_software.txt",
    "ipconfig.txt",
    "services.txt",
    "systeminfo.txt"
]

file_artifact = [
    "Windows\\system32\\config\\SYSTEM",
    "Windows\\system32\\config\\SOFTWARE",
    "Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    "Windows\\system32\\wbem\\Repository\\OBJECTS.DATA",
    "Windows\\system32\\wbem\\Repository\\FS\\OBJECTS.DATA"
    ]


computerName = get_computer_name()
platform = get_platform()
installTime = get_install_time()
localTimeZone = get_local_TimeZone()
ipAddr = get_ip_address()
runAsUser = get_run_as_user()
adminRights = has_admin_rights()
startTime = get_start_time()
endTime = atexit.register(get_end_time)
scanID = get_scanID()

systeminfor_folder = computerName + "_systeminfor"

