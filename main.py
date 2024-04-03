import sys
import argparse
import subprocess
sys.path.append('./config/config_ui')
sys.path.append('./core')
sys.path.append('./plugins')

from core.collection import *
from plugins.event_log import event_log_module
from plugins.process_scan import process_module  
from plugins.network import network_module  
from plugins.registry import registry_module
from plugins.files_scan import fileScan_module
from plugins.wmi import wmi_module
from core.condition import *
from core.matching import matching
import json

def clear_output_folder(check, output_folder_path):
    if check: return 0
    for root, dirs, files in os.walk(output_folder_path):
        for file in files:
                file_path = os.path.join(root, file)
                os.remove(file_path)
        for dir in dirs:
                dir_path = os.path.join(root, dir)
                shutil.rmtree(dir_path)

if __name__ == "__main__":    
        logo_filepath = ".\\data\\art\\logo.txt"
        with open(logo_filepath,"r",encoding='utf-8') as f:
                print(f.read())
        f.close()      
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
        try:
                outputFolder = create_new_folder(".", "output")
                extractFolder = create_new_folder(outputFolder,"extract")
                server = subprocess.Popen(command, shell=True)
                collect_system_info()
                collect_OBJECT_DATA(extractFolder,args.verbose)
                wmiOutput = wmi_module(extractFolder,outputFolder,args.verbose,args.save)
                networkOutput = network_module(outputFolder,args.verbose,args.save)
                regOutput = registry_module(outputFolder,args.verbose,args.save)
                if args.collect:
                        collect_evtx_file(extractFolder,args.verbose)
                eventLogOutput = event_log_module(args.verbose)
                processOutput = process_module(args.verbose)
                # # Initializing input for testing
                # outputFolder = "output"
                # networkOutput = []
                # eventLogOutput = []
                # regOutput = []
                # fileOutput = []
                # processOutput = []

                # filepath = ".\\output\\Network_module.json"
                # with open(filepath,"r",encoding='utf-8-sig') as f:
                #         networkOutput = eval(f.read())
                # f.close()

                # filepath = ".\\output\\HollowsHunter\\summary.json"
                # with open(filepath,"r",encoding='utf-8-sig') as f:
                #         processOutput = eval(f.read())
                # f.close()

                # filepath = ".\\output\\Files_module.json"
                # with open(filepath,"r",encoding='utf-8-sig') as f:
                #         fileOutput = eval(f.read())
                # f.close()

                # filepath = ".\\output\\Registry_module.json"
                # with open(filepath,"r",encoding='utf-8-sig') as f:
                #         # Normalizing Registry key path
                #         regOutput = eval(f.read().replace("null","0")\
                #                         .replace("HKEY_LOCAL_MACHINE","HKLM")\
                #                         .replace("HKEY_CLASSES_ROOT","HKCR")\
                #                         .replace("HKEY_CURRENT_USER","HKCU")\
                #                         .replace("HKEY_USERS","HKU")\
                #                         .replace("HKEY_CURRENT_CONFIG","HKCC"))
                # f.close()
                
                # filepath = ".\\output\\event-log-module-output.jsonl"
                # with open(filepath,"r",encoding='utf-8-sig') as file:
                #         for line in file:
                #                 eventLogOutput.append(json.loads(line))
                if args.fast:
                        matching(eventLogOutput,processOutput, networkOutput, regOutput, wmiOutput)
                else:
                        fileOutput = fileScan_module(outputFolder,args.verbose,args.save)
                        matching(eventLogOutput,processOutput, networkOutput, regOutput, wmiOutput, fileOutput)                      
                clear_output_folder(args.save, outputFolder)
                create_report()
        except KeyboardInterrupt:
                print("User cancelled the operation.")
        except Exception as e:
                print(f"An error occurred: {e}")
        finally:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Optional: hide window
                process = subprocess.Popen(["taskkill", "/F", "/T", "/PID", str(server.pid)], startupinfo=startupinfo)
                process.wait()
                print("+"*100)
