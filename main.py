import sys
import argparse
import subprocess
import ctypes
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
from plugins.wmi import wmi_module
from core.condition import *
from core.matching import matching

if __name__ == "__main__":          
        if check_port(8001):
                print("Port 8001 is already in use!")
                sys.exit()             
        if not is_admin():
                print("Please run as an administrator!")
                sys.exit() 
               
        parser = argparse.ArgumentParser(description="Hera is not thor")
        parser.add_argument("-cl", "--collect", action="store_true", help="Collect event log files")
        parser.add_argument("-sf", "--save", action="store_true", help="Save output to file")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
        parser.add_argument("-f", "--fast", action="store_true", help="Do not scan files for quick analysis")
        args = parser.parse_args()   
        velociraptor_executable = ".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
        artifacts_folder = ".\\data\\artifacts"
        server_config = ".\\config\\server.config.yaml"
        api_config = ".\\config\\api.config.yaml"
        create_api_config_command = [velociraptor_executable, "--config", server_config, "config", "api_client", "--name", "admin", "--role", "administrator", api_config]
        subprocess.run(create_api_config_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        command = [velociraptor_executable, "--definitions", artifacts_folder, "--config", server_config, "frontend"]
        # print(command)
        try:
                outputFolder = create_new_folder(".", "output")
                extractFolder = create_new_folder(outputFolder,"extract")
                systeminfoFolder = create_new_folder(".", "system_info")
                server = subprocess.Popen(command, shell=True)
                collect_system_info()
                collect_OBJECT_DATA(extractFolder,args.verbose)
                wmiOutput = wmi_module(extractFolder,outputFolder,args.verbose,args.save)
                if args.collect:
                        collect_evtx_file(extractFolder,args.verbose)
                eventLogOutput = event_log_module(args.verbose)
                processOutput = process_module(args.verbose)
                networkOutput = network_module(outputFolder,args.verbose,args.save)
                regOutput = registry_module(outputFolder,args.verbose,args.save)
                if args.fast:
                        matching(processOutput, regOutput, networkOutput, wmiOutput)
                else:
                        fileOutput = fileScan_module(outputFolder,args.verbose,args.save)
                        matching(processOutput, regOutput, networkOutput, wmiOutput, fileOutput)
                create_report()
        except Exception as e:
                print(f"An error occurred: {e}")
        finally:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Optional: hide window
                process = subprocess.Popen(["taskkill", "/F", "/T", "/PID", str(server.pid)], startupinfo=startupinfo)
                process.wait()
                print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
