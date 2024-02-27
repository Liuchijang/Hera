import subprocess
import os
import re
import json

def Run_velociraptor_artifact(artifact_name, verbose=False):
    # Path to executable of Velociraptor on Windows
    velociraptor_executable = r".\\velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, '--definitions', './Velociraptor artifacts', 'artifacts', "collect", artifact_name,'--format','json']
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True,encoding="utf-8")
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")
HayabusaArtifact = "Windows.EventLogs.LocalHayabusa"
output = Run_velociraptor_artifact(HayabusaArtifact)
correctSyntax = re.sub(r"\]\[", ",",output)
parsed = json.loads(correctSyntax)

# Optionally write output to file
cwd = os.getcwd()
filepath = os.path.join(cwd,"Event log module's output.json")
with open(filepath, 'wb') as f:
    f.write(output.encode('utf8', 'ignore'))
