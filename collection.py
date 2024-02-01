import sys
sys.path.append('./config_ui')

import os
import subprocess
import socket
import psutil
import platform
import datetime
import random
import string
from datetime import datetime
import pytz
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
    return psutil.WINDOWS and psutil.win_service_get("wuauserv") is not None

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

computerName = get_computer_name()
platform = get_platform()
installTime = get_install_time()
localTimeZone = get_local_TimeZone()
ipAddr = get_ip_address()
runAsUser = get_run_as_user()
adminRights = has_admin_rights()
startTime = get_start_time()
endTime = get_end_time()
scanID = get_scanID()
systeminfor_folder = computerName + "_systeminfor"
