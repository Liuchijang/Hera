import sys
import argparse
import subprocess

sys.path.append('./config_ui')

from config_ui.report_form import report_form
from collection import *

if __name__ == "__main__":

        parser = argparse.ArgumentParser(description="Hera is not thor")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
        args = parser.parse_args()

        velociraptor_executable = r".\\tools\\velociraptor-v0.7.1-1-windows-amd64.exe"
        artifacts_folder = ".\\artifacts"
        server_config = ".\\config\\server.config.yaml"
        command = [velociraptor_executable, "--definitions", artifacts_folder, "--config", server_config, "frontend"]
        subprocess.run(command, shell=True)

        create_new_folder(".", "system_info")
        collect_system_info()
        create_report()
