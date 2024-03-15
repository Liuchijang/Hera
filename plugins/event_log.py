from core.velociraptor_sever_api import Run_velociraptor_query
import json

def event_log_module(verbose=False):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nEventLogs scanning...")
    artifact = "Windows.EventLogs.LocalHayabusa"
    query = "select * from Artifact.{}()".format(artifact)
    Run_velociraptor_query(query)
    result = []
    filepath = ".\\output\\event-log-module-output.jsonl"
    with open(filepath,"r") as file:
        for line in file:
            result.append(json.loads(line))
    if verbose:
        for i in result:
            print("Timestamp:",i['Timestamp'],"\nRule Title:",i['RuleTitle'],"\n")
    print("Scan Event logs completed.")
    return result

if __name__ == "__main__":
    event_log_module()
