import re
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import check_virustotal

def network_module():
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nNetwork scanning...")
    networkArtifact = "Windows.Network.Scan"
    query = f"Select * from Artifact.{networkArtifact}()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    result = []
    print(parsed)
    for i in parsed:
        check = check_virustotal("check_ip", i['DestIP'])
        if check == 1:
            print(i["Path"] + '\n' + i["CommandLine"] + '\n' + i["DestIP"] + '\n')
            result.extend(i)
    return result

if __name__ == "__main__":
    network_module()