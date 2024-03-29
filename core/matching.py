from malware import *
import json
from collections import defaultdict
import os


malware_instances = []

def event_id_8(event_log, proc):
    result = []
    for event in event_log:
        if event['EventID'] == 8 \
            and ('hollows_hunter64.exe' not in event['Details']['SrcProc']) \
            and event['Details']['SrcPID'] == proc[0] \
            and event['Details']['SrcProc'] == proc[1]:
            tmp = event['Details']['TgtProc']
            result.append(tmp)
    return result

def event_id_13_to_reg(event_log, proc):
    result = []
    for event in event_log:
        if event['EventID'] == 13 \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]:
            tmp = (event['Details']['TgtObj'], event['Details'][''])
            result.append(tmp)
    return result

def event_id_13_to_cmdline(event_log, proc, cmdline):
    result = []
    for event in event_log:
        if event['EventID'] == 13 \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]\
            and (event['Details'][''] in cmdline or cmdline in event['Details']['']):
            tmp = (event['Details']['TgtObj'], event['Details'][''])
            result.append(tmp)
    return result

def event_id_11_to_dll(event_log, proc):
    # proc[0] is PID, proc[1] is Process Name
    result = []
    for event in event_log:
        if event['EventID'] == 11 \
            and event['Details']['Rule'] == 'DLL'  \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]:
            result.append(event['Details']['Path'])
    return result

def event_id_11_to_file(event_log, proc):
    # proc[0] is PID, proc[1] is Process Name
    result = []
    currentDirectory = os.getcwd()
    for event in event_log:
        if event['EventID'] == 11 \
            and 'Rule' in event['Details']\
            and event['Details']['Rule'] != 'DLL'  \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]\
            and currentDirectory not in event['Details']['Path']:
            result.append(event['Details']['Path'])
    return result

def hollowsHunter_to_dll(process, proc):
    result = []
    for sus in process['suspicious']:
        with open(rf".\output\HollowsHunter\process_{sus['pid']}\scan_report.json") as f:
            data = eval(f.read())
            if data['pid'] != proc[0] \
                or data['main_image_path'] != proc[1]:
                f.close()
                continue
            for i in data['scans']:
                for j in i.keys():
                    # whitelisting known legit dll
                    if 'module_file' in i[j]\
                        and i[j]['module_file'] != "C:\Windows\System32\\ntdll.dll":
                        if "dll" in i[j]['module_file']:
                            result.append(i[j]['module_file'])
        f.close()
    return result

def network_to_dll(network, proc):
    result = []
    for conn in network:
        if conn['Path'] == proc[1] \
            and conn['Pid'] == proc[0]:
            for dll in conn['ModulePath']:
                #just loaded dlls by process
                if "dll" in dll: 
                    result.append(dll)
    return result

def networkConnection(network, proc):
    result = []
    for conn in network:
        if conn['Path'] == proc[1] \
            and conn['Pid'] == proc[0]:
            connection = {'SrcIP': conn['SrcIP'],'SrcPort': conn['SrcPort'],'DestIP': conn['DestIP'],'DestPort': conn['DestPort']}
            result.append(connection)
    return result

def wmi_to_cmdline(wmi, commandline):
    result = []
    for i in wmi:
        if 'Arguments' in i and commandline.replace("\"","").replace("\\","") in i['Arguments'].replace("\"","").replace("\\",""):
            result.append((i['Consumer Name'],i['Arguments']))
    return result

def reg_to_cmdline(reg, commandline, result):
    for i in reg:
        if type(i['Contents']) == type(commandline) \
            and (i['Contents'] in commandline or commandline in i['Contents']):
            result.append((i['ValueName'],i['Contents']))
    return result

def file_to_cmdline(files, commandline):
    result = []
    for file in files:
        if file['OSPath'].split("\\")[-1] in commandline:
            result.append(file['OSPath'])
    return result

def create_process_tree(event_log):
    # Hiển thị cây quan hệ giữa PID và ProcessId
    lst = []
    process_tree = []
    for i in event_log:
        if i['EventID'] == 4688 and 'ExtraFieldInfo' in i and 'ParentProcessName' in i['ExtraFieldInfo']:
            lst.append(i)
    # print(event_log[0]['Timestamp'])
    pid_to_ppid = defaultdict(list)
    pid_to_cmd = defaultdict(list)
    ppid_to_name = defaultdict(list)
    pid_to_name = defaultdict(list)
    # Đổ dữ liệu từ danh sách vào defaultdict
    for item in lst:
        pid = item['Details']['PID']
        ppid = item['ExtraFieldInfo']['ProcessId']
        lid = item["Details"]['LID']
        cmd = item['Details']['Cmdline']
        pid_to_ppid[(ppid, lid)].append((pid, lid))
        pid_to_cmd[(pid, lid)] = cmd
        pid_to_name[(pid, lid)] = item['Details']['Proc']
        if 'ExtraFieldInfo' in item and 'ParentProcessName' in item['ExtraFieldInfo']:
            ppid_to_name[(ppid, lid)] = item['ExtraFieldInfo']['ParentProcessName']
        else: ppid_to_name[(ppid, lid)] = ""

    def display_tree(ppid, pid_dict, prefix='', is_first=True, is_last=True, level=0):
        if is_last and is_first:
            pid_dict[ppid[0], ppid_to_name[ppid]] = ("", level)
            level = level + 1
            # print()
            # print(prefix + '└── ' + f"{ppid[0]} - {ppid_to_name[ppid]}")
        elif is_last and not is_first:
            pid_dict[ppid[0], pid_to_name[ppid]] = (pid_to_cmd[ppid], level)
            level = level + 1
            # print(prefix + '└── ' + f"{ppid[0]} - {pid_to_cmd[ppid]}")    
        else:
            pid_dict[ppid[0], pid_to_name[ppid]] = (pid_to_cmd[ppid], level)
            # print(prefix + '├── ' + f"{ppid[0]} - {pid_to_cmd[ppid]}")
        children = pid_to_ppid.get(ppid, [])
        count = len(children)
        for i, child_pid in enumerate(children, 1):
            is_first = False
            is_last = i == count
            display_tree(child_pid, pid_dict , prefix + ('    ' if is_last else '│   '), False, is_last, level)
            
    # Tạo một tập hợp duy nhất của tất cả các phần tử từ tập hợp các giá trị
    all_ppids = set(pid for sublist in pid_to_ppid.values() for pid in sublist)

    # Tìm PPID gốc (PPID không phải là PID của bất kỳ tiến trình nào)
    root_ppids = set(pid_to_ppid.keys()) - all_ppids
    for root_pid in root_ppids:
        pid_dict = defaultdict(list)
        display_tree(root_pid, pid_dict)
        process_tree.append(pid_dict)
    return process_tree

def match_pid_name_dll(event_log, process, network=None):
    # Value of Detected key in DLL attribute: 0 means the process had loaded dll, 1 means that dll was loaded and detected as suspicious
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            event_log_matches = event_id_11_to_dll(event_log,proc)
            for i in event_log_matches:
                malware_instances[index].add_dll(proc,(i,1))
            process_matches = hollowsHunter_to_dll(process,proc)
            for i in process_matches:
                malware_instances[index].add_dll(proc,(i,1))
            if network:
                network_matches = network_to_dll(network,proc)
                for i in network_matches:
                    malware_instances[index].add_dll(proc,(i,0))

def match_pid_name_network(network):
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            connections = networkConnection(network, proc)
            for conn in connections:
                malware_instances[index].add_network_activity(proc,conn)

def match_pid_name_registry(event_log):
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            result = event_id_13_to_reg(event_log, proc)
            for i in result:    
                malware_instances[index].add_registry_entry(proc, i)

def match_pid_name_files(event_log):
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            injected_file = event_id_8(event_log, proc)
            for i in injected_file:
                malware_instances[index].add_file(proc, (i,"injected"))
            created_files = event_id_11_to_file(event_log,proc)
            for i in created_files:
                malware_instances[index].add_file(proc,(i,"created"))

def match_cmdline(event_log, wmi,reg,files=None):
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            # malware.process[proc][0] is command line of process
            if malware.process[proc][0] != "":
                wmiConsumers = wmi_to_cmdline(wmi,malware.process[proc][0])
                if len(wmiConsumers) > 0:
                    for consumer in wmiConsumers:
                        if consumer not in malware_instances[index].wmi:
                            malware_instances[index].add_wmi(consumer)
                regKeys_eventID13 = event_id_13_to_cmdline(event_log,proc,malware.process[proc][0])
                regKeys = reg_to_cmdline(reg,malware.process[proc][0],regKeys_eventID13)
                if len(regKeys) > 0:
                    for regkey in regKeys:
                        if regkey not in malware_instances[index].registry:
                            malware_instances[index].add_registry_entry(proc,regkey)
                if files and len(files) > 0: 
                    detected = file_to_cmdline(files,malware.process[proc][0])
                    if len(detected) > 0:
                        for file in detected:
                            if file not in malware_instances[index].files:
                                # detected means that it is detected by file module
                                malware_instances[index].add_file(proc,(file,"detected"))
                
                

def creat_object(process_tree, event_log, process, network):
    for i in process_tree:
        malware_instances.append(Malware(i))
    for sus in process['suspicious']:
        with open(rf".\output\HollowsHunter\process_{sus['pid']}\scan_report.json") as f:
            proc = eval(f.read())
            isContained = False
            for p in process_tree:
                if (proc['pid'],proc['main_image_path'])  in p.keys():
                    isContained = True
            if not isContained: 
                processBehavior = defaultdict(list)
                processBehavior[proc['pid'], proc['main_image_path']] = ("", 0)
                malware = Malware(processBehavior)
                # for i in proc['scans']:
                #     for j in i.keys():
                #         if 'module_file' in i[j]:
                #             # Whitelisting known legit dll
                #             if i[j]['module_file'].replace("\\","").lower() == "C:\Windows\System32\\ntdll.dll".replace("\\","").lower(): continue
                #             if "dll" in i[j]['module_file']: malware.add_dll((i[j]['module_file'],1))
                #             else: malware.add_file((i[j]['module_file'],1))
                malware_instances.append(malware)
        f.close()
    if len(network) > 0:
        for conn in network:
            isContained = False
            for m in malware_instances:
                if (conn['Pid'],conn['Path'])  in m.process:
                    isContained = True
            if not isContained: 
                processBehavior = defaultdict(list)
                processBehavior[conn['Pid'],conn['Path']] = (conn['CommandLine'], 0)
                malware = Malware(processBehavior)
                malware_instances.append(malware)
    for event in event_log:
        if event['EventID'] == 13:
            isContained = False
            for m in malware_instances:
                if (event['Details']['PID'],event['Details']['Proc'])  in m.process:
                    isContained = True
            if not isContained:
                processBehavior = defaultdict(list)
                processBehavior[event['Details']['PID'],event['Details']['Proc']] = ("", 0)
                malware = Malware(processBehavior)
                malware_instances.append(malware)

def matching(event_log, process, network, registry, wmi,files=None):
    creat_object(create_process_tree(event_log),event_log,process,network)
    match_pid_name_dll(event_log,process,network)
    if len(network) > 0: 
        match_pid_name_network(network)
    match_pid_name_registry(event_log)
    match_pid_name_files(event_log)
    if files: 
        match_cmdline(event_log,wmi,registry,files)
    else: 
        match_cmdline(event_log,wmi,registry)
    for i in malware_instances:
        i.display()
        print("")
if __name__ == "__main__":
        # Initializing input for testing
    network = []
    event_log = []
    registry = []
    process = []

    filepath = ".\\output\\Network_module.json"
    with open(filepath,"r",encoding='latin-1') as f:
        network = eval(f.read())
    f.close()

    filepath = ".\\output\\HollowsHunter\\summary.json"
    with open(filepath,"r",encoding='latin-1') as f:
        process = eval(f.read())
    f.close()

    filepath = ".\\output\\Registry_module.json"
    with open(filepath,"r",encoding='latin-1') as f:
        # Normalizing Registry key path
        registry = eval(f.read().replace("null","0")\
                        .replace("HKEY_LOCAL_MACHINE","HKLM")\
                        .replace("HKEY_CLASSES_ROOT","HKCR")\
                        .replace("HKEY_CURRENT_USER","HKCU")\
                        .replace("HKEY_USERS","HKU")\
                        .replace("HKEY_CURRENT_CONFIG","HKCC"))
    f.close()
    
    filepath = ".\\output\\event-log-module-output.jsonl"
    with open(filepath,"r",encoding='latin-1') as file:
        for line in file:
            event_log.append(json.loads(line))
    process_tree = create_process_tree(event_log)
        # Displaying suspicious objects
    matching(event_log, process, network)