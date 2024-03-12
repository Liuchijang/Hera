import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def process_module():
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nProcesses scanning...")
    artifact = "Windows.Memory.LocalHollowsHunter"
    query = "select * from Artifact.{}()".format(artifact)
    Run_velociraptor_query(query)
    with open(".\output\HollowsHunter\summary.json","r") as file:
        output = file.read()
        parsedOutput = eval(output)
        # verbose: print output to screen
        print("Process Scan time:",parsedOutput['scan_date_time'],
              "\nTotal scan time in ms:",parsedOutput['scan_time_ms'],
              "\nTotal scanned processes:",parsedOutput['scanned_count'],
              "\nSuspicious process count:",parsedOutput['suspicious_count'],
              "\n+++++++++++++ Suspicious processes infomartion +++++++++++++")
        for suspicious in parsedOutput['suspicious']:
            print("Process ID:",suspicious['pid'])
            print("Process Name:",suspicious['name'])
            with open(f".\output\HollowsHunter\process_{suspicious['pid']}\scan_report.json") as proc:   
                data = eval(proc.read())
                print("Image Fullpath:",data['main_image_path'])
                for i in data['scans']:
                    if 'code_scan' in i:
                        print("Suspicious Module (Triggered by code scan):",i['code_scan']['module_file'])
                    if 'mapping_scan' in i:
                        print("Suspicious Module (Triggered by mapping scan):",i['mapping_scan']['mapped_file'])
                        print("\t\t\t\t\t      ",i['mapping_scan']['module_file'])
            print("")



if __name__ == "__main__":
    process_module()