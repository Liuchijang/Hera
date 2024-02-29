import os
import re
import json
from velociraptor_sever_api import Run_velociraptor_query

def network_module():
    Artifact = "Windows.Network.NetstatEnriched"
    query = "Select * from Artifact.Windows.Network.NetstatEnriched()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = json.loads(correctSyntax)

    # Optionally write output to file
    cwd = os.getcwd()
    filepath = os.path.join(cwd,"network-activities-of-processes.json")
    with open(filepath, 'wb') as f:
        f.write(output.encode('utf8', 'ignore'))
