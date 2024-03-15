import os
import re
import json
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import *

def network_module(outputFolder, verbose=False,save_to_file=False):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nNetwork scanning...")
    networkArtifact = "Windows.Network.Scan"
    query = f"Select * from Artifact.{networkArtifact}()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    malicious_ip = []
    result = []
    if check_connect():
        for i in parsed:
            check = check_virustotal("check_ip", i['DestIP'])
            if check == 1:
                if verbose: print("Path: " + i["Path"] + '\n' + "CommandLine: " + i["CommandLine"] + '\n' + "Destination IP: " + i["DestIP"] + '\n')
                result.append(i)
    else:
        with open("./data/malicious_ip.txt", "r") as f:
            malicious_ip = set(line.strip() for line in f)
        for i in parsed:
            if i['DestIP'] in malicious_ip:
                if verbose: print("Path: " + i["Path"] + '\n' + "CommandLine: " + i["CommandLine"] + '\n' + "Destination IP: " + i["DestIP"] + '\n')
                result.append(i)
    if save_to_file:
        filepath = os.path.join(outputFolder,"Network_module.json")
        with open(filepath, 'w') as f:
            json.dump(result,f,indent=4)
            print(f"Saved network module output at {filepath}")
    print("Scan Network connections completed.")
    return result

if __name__ == "__main__":
    network_module()