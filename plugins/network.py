from core.velociraptor_sever_api import Run_velociraptor_query

def network_module():
    networkArtifact = "Windows.Network.NetstatEnriched"
    query = f"Select * from Artifact.{networkArtifact}()"
    netstat = Run_velociraptor_query(query)
    dllArtifact = "Windows.System.DLLs"
    query = f"Select * from Artifact.{dllArtifact}()"
    loadedDLL = Run_velociraptor_query(query)
    listConnection = eval(netstat)
    listDLL = eval(loadedDLL)
    combined_data = {}
    for dll_item in listDLL:
        pid = dll_item['Pid']
        if pid not in combined_data:
            combined_data[pid] = {'DLL': [], 'Connection': []}
        combined_data[pid]['DLL'].append(dll_item)
    for connection_item in listConnection:
        pid = connection_item['Pid']
        if pid not in combined_data:
            combined_data[pid] = {'DLL': [], 'Connection': []}
        combined_data[pid]['Connection'].append(connection_item)
    with open("network-module-output.txt", "w") as file:
        for pid, data in combined_data.items():
            file.write(f"\n-------------------------------------------------------------------------------------\n")
            file.write(f"Pid: {pid}\n")
            file.write(f"-----------------------------------Loaded DLL----------------------------------------\n")
            if 'DLL' in data and data['DLL']:
                file.write(f"Executable name: {str(data['DLL'][0]['Name'])}\n")
                file.write(f"Executable Fullpath: {str(data['DLL'][0]['_Exe'])}\n")
                file.write(f"Command line: {str(data['DLL'][0]['_CommandLine'])}\n")
                for dll_item in data['DLL']:
                # Print the 'ModulePath' value if it exists
                    if 'ModulePath' in dll_item:
                        file.write(f"DLL Fullpath: {str(dll_item['ModulePath'])}\n")
            file.write(f"-------------------------------------Connection--------------------------------------\n")
            #file.write(str(data['Connection']) + "\n")  # Convert list to string
            if 'Connection' in data and data['Connection']:
                count = 1
                file.write(f"Pid: {str(data['Connection'][0]['Pid'])}\n")
                file.write(f"PPid: {str(data['Connection'][0]['Ppid'])}\n")
                file.write(f"Executable Name: {str(data['Connection'][0]['Name'])}\n")
                file.write(f"Executable Fullpath: {str(data['Connection'][0]['Path'])}\n")
                file.write(f"Command line: {str(data['Connection'][0]['CommandLine'])}\n")
                file.write(f"Hash: {str(data['Connection'][0]['Hash'])}\n")
                for connection_item in data['Connection']:
                    if 'DestIP' in connection_item:
                        file.write(f"------Connection {count}------\n")
                        count+=1
                        file.write(f"Username: {str(connection_item['Username'])}\n")
                        file.write(f"Status: {str(connection_item['Status'])}\n")
                        file.write(f"Source IP address: {str(connection_item['SrcIP'])}\n")
                        file.write(f"Source IP port: {str(connection_item['SrcPort'])}\n")
                        file.write(f"Destination IP address: {str(connection_item['DestIP'])}\n")
                        file.write(f"Destination IP port: {str(connection_item['DestPort'])}\n")
                        file.write(f"Timestamp: {str(connection_item['Timestamp'])}\n")
                        file.write(f"Authenticode: {str(connection_item['Authenticode'])}\n")

    print("Network information and Loaded DLL of process is written to network-module-output.txt")
if __name__ == "__main__":
    network_module()