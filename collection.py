import socket
import psutil
import platform
import datetime
import random
import string
from datetime import datetime, timedelta

def get_computer_name():
    return socket.gethostname()

def get_platform():
    return platform.platform()

def get_install_time():
    return datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    # return datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

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


computerName = get_computer_name()
platform = get_platform()
installTime = get_install_time()
ipAddr = get_ip_address()
runAsUser = get_run_as_user()
adminRights = has_admin_rights()
startTime = get_start_time()
endTime = get_end_time()
scanID = get_scanID()

