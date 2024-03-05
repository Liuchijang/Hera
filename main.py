import sys
import argparse
import subprocess

sys.path.append('./config_ui')

from config_ui.report_form import report_form
from collection import *
from event_log import event_log_module
from process_scan import process_module  
from network import network_module  
from registry import registry_module

if __name__ == "__main__":

        parser = argparse.ArgumentParser(description="Hera is not thor")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
        args = parser.parse_args()

        velociraptor_executable = ".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
        artifacts_folder = ".\\Velociraptor_artifacts"
        server_config = ".\\config\\server.config.yaml"
        command = [velociraptor_executable, "--definitions", artifacts_folder, "--config", server_config, "frontend"]
        # print(command)
        try:
                server = subprocess.Popen(command, shell=True)
                # systeminfoFolder = create_new_folder(".", "system_info")
                # extractFolder = create_new_folder(".", "extract")
                collect_system_info()
                # collect_OBJECT_DATA(extractFolder)
                # collect_evtx_file(extractFolder)
                # event_log_module()
                # process_module()
                # network_module()
                registry_module()
                create_report()
        except Exception as e:
                print(f"An error occurred: {e}")
        finally:
                server.terminate()
