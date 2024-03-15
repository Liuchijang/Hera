import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query


def event_log_module(outputFolder=None, verbose=False, save_to_file=False):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nEventLogs scanning...")
    artifact = "Windows.EventLogs.LocalHayabusa"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    parse = eval(output)
    if verbose:
        for i in parse:
            if '\"Timestamp\"' in i['Stdout']:
                print("\nTimestamp:",i['Stdout'].split("\"")[3])
            if '\"RuleTitle\"' in i['Stdout']:
                print("RuleTitle:",i['Stdout'].split("\"")[3])
    print("Scan Event logs completed.")
    return parse

if __name__ == "__main__":
    event_log_module()
