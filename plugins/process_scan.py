import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def process_module():
    Artifact = "Windows.Memory.LocalHollowsHunter"
    query = "select * from Artifact.Windows.Memory.LocalHollowsHunter()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    print(output)

if __name__ == "__main__":
    process_module()