import re
from core.velociraptor_sever_api import Run_velociraptor_query

def fileScan_module():
    artifact = "Files.scan"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    print(parsed)
    return parsed


if __name__ == "__main__":
    fileScan_module()
