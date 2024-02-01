import sys
sys.path.append('./config_ui')

import os
import subprocess
import ctypes
import socket
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

@process_bar
def create_sysinfo_file(command, file_name):
    try:
        # print(message)
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, text=True)
        with open(os.path.join(systeminfor_folder, file_name), 'w') as file:
            file.write(result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing {command}: {e}")

def collect_system_info(message_list, command_list, file_list):
    for message, command, file in zip(message_list, command_list, file_list):
        print(message)       
        create_sysinfo_file(command, file)

def create_vss():
    volume_path = "C:\\"
    powershell_command = f'powershell.exe -Command "Invoke-CimMethod -MethodName Create -ClassName Win32_ShadowCopy -Arguments @{{ Volume= \'{volume_path}\' }}"'
    try:
        result = subprocess.run(powershell_command, shell=True, check=True, capture_output=True, text=True)
        print("Volume Shadow Copy created successfully.")
        pattern = r"\{(.*?)\}"
        shadow_id_match = re.search(pattern, result.stdout)
        if shadow_id_match:
            shadow_id = shadow_id_match.group(1)  # Access the captured value
            print("Extracted ShadowID:", shadow_id)
            return "{"+shadow_id+"}"
    except subprocess.CalledProcessError as e:
        print(f"Error creating Volume Shadow Copy: {e}")

def list_vss_shadows(shadow_id):
    """Lists available VSS shadows using the 'vssadmin list shadows' command."""
    command = f'cmd.exe /c "vssadmin list shadows /shadow={shadow_id}"'
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        vss_output = result.stdout
        return vss_output
    except subprocess.CalledProcessError as error:
        print("Error listing VSS shadows:", error)
    
def copy_locked_file_from_latest_vss(shadow_id, file_path,des_path):
    """Copies a file from the latest VSS shadow to the destination directory."""
    vss_output = list_vss_shadows(shadow_id)
    filename = file_path.split("\\")[-1]
    if vss_output:
        latest_vss_guid = re.search(r"Shadow Copy Volume: (\\\\.*?)\n", vss_output).group(1)
        source_path = f"{latest_vss_guid}\\{file_path}"
        try:
            command = f'cmd.exe /c "copy {source_path} {des_path}\\{filename}" '
            subprocess.run(command, shell=True, check=True)
            print(f"File copied successfully from VSS shadow: {source_path} to {des_path}\\{filename}")
        except Exception as error:
            print("Error copying file:", error)
    else:
        print("Failed to retrieve VSS information.")

def create_vss():
    volume_path = "C:\\"
    powershell_command = f'powershell.exe -Command "Invoke-CimMethod -MethodName Create -ClassName Win32_ShadowCopy -Arguments @{{ Volume= \'{volume_path}\' }}"'
    try:
        result = subprocess.run(powershell_command, shell=True, check=True, capture_output=True, text=True)
        print("Volume Shadow Copy created successfully.")
        pattern = r"\{(.*?)\}"
        shadow_id_match = re.search(pattern, result.stdout)
        if shadow_id_match:
            shadow_id = shadow_id_match.group(1)  # Access the captured value
            print("Extracted ShadowID:", shadow_id)
            return "{"+shadow_id+"}"
    except subprocess.CalledProcessError as e:
        print(f"Error creating Volume Shadow Copy: {e}")

def list_vss_shadows(shadow_id):
    """Lists available VSS shadows using the 'vssadmin list shadows' command."""
    command = f'cmd.exe /c "vssadmin list shadows /shadow={shadow_id}"'
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        vss_output = result.stdout
        return vss_output
    except subprocess.CalledProcessError as error:
        print("Error listing VSS shadows:", error)
    
def copy_locked_file_from_latest_vss(shadow_id, file_path,des_path):
    """Copies a file from the latest VSS shadow to the destination directory."""
    vss_output = list_vss_shadows(shadow_id)
    filename = file_path.split("\\")[-1]
    if vss_output:
        latest_vss_guid = re.search(r"Shadow Copy Volume: (\\\\.*?)\n", vss_output).group(1)
        source_path = f"{latest_vss_guid}\\{file_path}"
        try:
            command = f'cmd.exe /c "copy {source_path} {des_path}\\{filename}" '
            subprocess.run(command, shell=True, check=True)
            print(f"File copied successfully from VSS shadow: {source_path} to {des_path}\\{filename}")
        except Exception as error:
            print("Error copying file:", error)
    else:
        print("Failed to retrieve VSS information.")

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

shadow_id = create_vss()
current_directory = os.getcwd()
for file in file_artifact:
    copy_locked_file_from_latest_vss(shadow_id,file,current_directory)
