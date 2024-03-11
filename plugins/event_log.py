import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def event_log_module(outputFolder):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nEventLogs scanning...")
    artifact = "Windows.EventLogs.LocalHayabusa"
    query = "select * from Artifact.{}()".format(artifact)

    output = Run_velociraptor_query(query)
    # correctSyntax = re.sub(r"\]\[", ",",output)
    # parsed = eval(correctSyntax)

    # Optionally write output to file
    filepath = os.path.join(outputFolder,"Event_log_module_commandLine_log.json")

    with open(filepath, 'wb') as f:
        f.write(output.encode('utf8', 'ignore'))

if __name__ == "__main__":
    event_log_module()
