import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def process_module():
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nProcesses scanning...")
    artifact = "Windows.Memory.LocalHollowsHunter"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    print(output)

if __name__ == "__main__":
    process_module()