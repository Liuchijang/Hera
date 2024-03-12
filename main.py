import sys
import argparse
import subprocess
import psutil

sys.path.append('./config/config_ui')
sys.path.append('./core')
sys.path.append('./plugins')

from config.config_ui.report_form import report_form
from core.collection import *
from plugins.event_log import event_log_module
from plugins.process_scan import process_module  
from plugins.network import network_module  
from plugins.registry import registry_module
from plugins.files_scan import fileScan_module
import ctypes
import os

if __name__ == "__main__":
        def kill_process_on_port(port):
                for proc in psutil.process_iter(['pid', 'name']):
                        for conns in proc.connections(kind='inet'):
                                if conns.laddr.port == port:
                                        proc.kill()
        def is_admin():
                try:
                        return ctypes.windll.shell32.IsUserAnAdmin()
                except:
                        return False

        if not is_admin():
                print("Please run as an administrator.")
                sys.exit()
        parser = argparse.ArgumentParser(description="Hera is not thor")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
        args = parser.parse_args()
        subprocess.run([".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe", "--config", ".\\config\\server.config.yaml", "config", "api_client", "--name", "admin", "--role", "administrator", ".\\config\\api.config.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        velociraptor_executable = ".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
        artifacts_folder = ".\\data\\artifacts"
        server_config = ".\\config\\server.config.yaml"
        command = [velociraptor_executable, "--definitions", artifacts_folder, "--config", server_config, "frontend"]
        # print(command)
        
        try:
                cwd = os.getcwd()
                outputFolder = create_new_folder(extract_base_folder(cwd), "output")
                server = subprocess.Popen(command, shell=True)
                # systeminfoFolder = create_new_folder(".", "system_info")
                # extractFolder = create_new_folder(".", "extract")
                collect_system_info()
                # collect_OBJECT_DATA(extractFolder)
                # collect_necessary_evtx(extractFolder)
                # collect_evtx_file(extractFolder)
                # event_log_module(outputFolder)
                # process_module()
                #network_module()
                # registry_module()
                # fileScan_module()
                # create_report()
        except Exception as e:
                print(f"An error occurred: {e}")
        finally:
                print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
                server.terminate()
                kill_process_on_port(8001)
                print("Terminated server")
         
