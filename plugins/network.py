import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import *

def network_module(outputFolder, save_to_file=False):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nNetwork scanning...")
    networkArtifact = "Windows.Network.Scan"
    query = f"Select * from Artifact.{networkArtifact}()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    result = []
    if check_connect():
        for i in parsed:
            check = check_virustotal("check_ip", i['DestIP'])
            if check == 1:
                print("Path: " + i["Path"] + '\n' + "CommandLine: " + i["CommandLine"] + '\n' + "Destination IP: " + i["DestIP"] + '\n')
                result.extend(i)
    else:
        with open("./data/malicious_ip.txt", "r") as f:
            malicious_ip = set(line.strip() for line in f)
        for i in parsed:
            if i['DestIP'] in malicious_ip:
                print("Path: " + i["Path"] + '\n' + "CommandLine: " + i["CommandLine"] + '\n' + "Destination IP: " + i["DestIP"] + '\n')
                result.extend(i)
    if save_to_file:
        filepath = os.path.join(outputFolder,"Network_module.json")
        with open(filepath, 'wb') as f:
            f.write(result.encode('utf8', 'ignore'))
    return result

if __name__ == "__main__":
    network_module()