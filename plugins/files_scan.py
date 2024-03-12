import re
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import *

def fileScan_module():
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nFiles scanning...")
    artifact = "Files.scan"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    result = []
    if check_connect():
        for i in parsed:
            check = check_virustotal("check_hash", i['MD5'])
            if check == 1:
                print("File Path: " + i['OSPath'])
                result.extend(i)
    else:
        with open("./data/malicious_MD5.txt", "r") as f:
            malicious_MD5 = set(line.strip() for line in f)
        for i in parsed:
            if i['MD5'] in malicious_MD5:
                print("File Path: " + i['OSPath'])
                result.extend(i)
    return result
    

if __name__ == "__main__":
    fileScan_module()
