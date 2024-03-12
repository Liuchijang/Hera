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
        return result
    else:
        for i in parsed:
            print("File Path: " + i['OSPath'])
        return parsed
    


if __name__ == "__main__":
    fileScan_module()
