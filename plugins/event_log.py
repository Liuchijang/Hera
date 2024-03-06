import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def event_log_module():
    Artifact = "Windows.EventLogs.LocalHayabusa"
    query = "select * from Artifact.Windows.EventLogs.LocalHayabusa()"
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)

    # Optionally write output to file
    cwd = os.getcwd()
    filepath = os.path.join(cwd,"Event-log-module-commandLine-log.json")
    with open(filepath, 'wb') as f:
        f.write(output.encode('utf8', 'ignore'))

if __name__ == "__main__":
    event_log_module()
