import os
import re
import json
from velociraptor_sever_api import Run_velociraptor_query


def event_log_module():
    Artifact = "Windows.EventLogs.LocalHayabusa"
    query = "select * from Artifact.Windows.EventLogs.LocalHayabusa()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = json.loads(correctSyntax)

    # Optionally write output to file
    cwd = os.getcwd()
    filepath = os.path.join(cwd,"Event log module's output.json")
    with open(filepath, 'wb') as f:
        f.write(output.encode('utf8', 'ignore'))
