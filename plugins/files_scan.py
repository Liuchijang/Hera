import re
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import check_virustotal

def fileScan_module():
    artifact = "Files.scan"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    result = []
    for i in parsed:
        check = check_virustotal("check_hash", i['MD5'])
        if check == 1:
            print(i['OSPath'])
            result.extend(i)
    return result


if __name__ == "__main__":
    fileScan_module()
