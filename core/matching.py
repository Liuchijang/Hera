from malware import *
from collections import defaultdict
import os
from plugins.files_scan import check_file


malware_instances = []
malware_instances_res = []

def event_id_8(event_log, proc):
    result = []
    for event in event_log:
        if event['EventID'] == 8 \
            and ('hollows_hunter64.exe' not in event['Details']['SrcProc']) \
            and event['Details']['SrcPID'] == proc[0] \
            and event['Details']['SrcProc'] == proc[1]:
            tmp = event['Details']['TgtProc']
            if tmp not in result:
                result.append(tmp)
    return result

def event_id_13_to_reg(event_log, proc):
    result = []
    for event in event_log:
        if event['EventID'] == 13 \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]:
            tmp = (event['Details']['TgtObj'], event['Details'][''])
            if tmp not in result:
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
            if tmp not in result:
                result.append(tmp)
    return result

def event_id_11_to_dll(event_log, proc):
    # proc[0] is PID, proc[1] is Process Name
    result = []
    for event in event_log:
        if event['EventID'] == 11 \
            and event['Details']['Rule'] == 'DLL'  \
            and event['Details']['PID'] == proc[0] \
            and event['Details']['Proc'] == proc[1]\
            and event['Details']['Path'] not in result:
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
            and currentDirectory not in event['Details']['Path']\
            and event['Details']['Path'] not in result:
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
                        and i[j]['module_file'] != "C:\\Windows\\System32\\ntdll.dll":
                        if "dll" in i[j]['module_file'] and i[j]['module_file'] not in result:
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
                if "dll" in dll and dll not in result: 
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
            if (i['Consumer Name'],i['Arguments']) not in result: 
                result.append((i['Consumer Name'],i['Arguments']))
    return result

def reg_to_cmdline(reg, commandline, result):
    for i in reg:
        if type(i['Contents']) ==  type("") \
            and type(commandline) == type("") \
            and (i['Contents'].replace("\"","") in (commandline.replace("\"","")) \
                 or commandline.replace("\"","") in (i['Contents']).replace("\"",""))\
            and ((len(i['Contents'])> len(commandline) and len(i['Contents']) - len(commandline) < 30)\
                 or(len(i['Contents'])< len(commandline) and len(commandline) -  len(i['Contents']) < 30)):
            if (i['ValueName'],i['Contents']) not in result: 
                result.append((i['ValueName'],i['Contents']))
    return result

def file_to_cmdline(files, processName):
    result = []
    for file in files:
        if file['OSPath'].split("\\")[-1] in processName:
            result.append(file['OSPath'])
    return result

def create_process_tree(event_log):
    pid_to_ppid = defaultdict(list)
    pid_to_cmd = defaultdict(list)
    ppid_to_cmd = defaultdict(list)
    ppid_to_name = defaultdict(list)
    pid_to_name = defaultdict(list)
    # Hiển thị cây quan hệ giữa PID và ProcessId
    lst = []
    process_tree = []

    check = False
    for i in event_log:
        if i["Channel"] == "Sysmon" and i['EventID'] == 1:
            check = True
    for i in event_log:
        if check:
            if i["Channel"] == "Sysmon" and i['EventID'] == 1:
                lst.append(i)
        else:
            if i['EventID'] == 4688 and 'ExtraFieldInfo' in i and 'ParentProcessName' in i['ExtraFieldInfo']:
                lst.append(i)
    # Đổ dữ liệu từ danh sách vào defaultdict
    for item in lst:
        if item['EventID'] == 4688:
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
        else:
            pid = item['Details']['PID']
            ppid = item['Details']['ParentPID']
            lid = item["Details"]['LID']
            cmd = item['Details']['Cmdline']
            pcmd = item['Details']['ParentCmdline']
            pid_to_ppid[(ppid, lid)].append((pid, lid))
            pid_to_cmd[(pid, lid)] = cmd
            ppid_to_cmd[(ppid, lid)] = pcmd
            pid_to_name[(pid, lid)] = item['Details']['Proc']
            if 'ExtraFieldInfo' in item and 'ParentImage' in item['ExtraFieldInfo']:
                ppid_to_name[(ppid, lid)] = item['ExtraFieldInfo']['ParentImage']
            else: ppid_to_name[(ppid, lid)] = ""

    def display_tree(ppid, pid_dict, prefix='', is_first=True, is_last=True, level=0):
        if is_last and is_first:
            pid_dict[ppid[0], ppid_to_name[ppid]] = (ppid_to_cmd[ppid], level)
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
                if i not in malware_instances[index].files:
                    malware_instances[index].add_file(proc, (i,"injected"))
            created_files = event_id_11_to_file(event_log,proc)
            for i in created_files:
                if i not in malware_instances[index].files:
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

def match_files(files):
    global malware_instances
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            detected = file_to_cmdline(files,proc[1])
            if len(detected) > 0:
                for file in detected:
                    if len(malware_instances[index].files) == 0:
                        if file == proc[1]: 
                            malware_instances[index].add_file(proc,(file,"detected"))
                        else:
                            malware_instances[index].add_file(proc,(file,"contained"))
                    else:
                        contained = False
                        for i in malware_instances[index].files:
                        # "detected" means that it is detected by file module
                        # "contained" means that it has similar filename to the process
                            if proc in i:
                                contained = True
                        if not contained: 
                            if file == proc[1]:
                                malware_instances[index].add_file(proc,(file,"detected"))
                            else:
                                malware_instances[index].add_file(proc,(file,"contained"))

def creat_object(process_tree, event_log, process, network):
    global malware_instances 
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
    global malware_instances 
    global malware_instances_res
    reg_temp = []
    for i in registry:
        temp = eval(str(i).replace("null","0")\
            .replace("HKEY_LOCAL_MACHINE","HKLM")\
            .replace("HKEY_CLASSES_ROOT","HKCR")\
            .replace("HKEY_CURRENT_USER","HKCU")\
            .replace("HKEY_USERS","HKU")\
            .replace("HKEY_CURRENT_CONFIG","HKCC"))
        reg_temp.append(temp)
    registry = reg_temp
    creat_object(create_process_tree(event_log),event_log,process,network)
    match_pid_name_dll(event_log,process,network)
    if len(network) > 0: 
        match_pid_name_network(network)
    match_pid_name_registry(event_log)
    match_pid_name_files(event_log)
    if files and len(files) > 0:
        match_files(files)
    if files: 
        match_cmdline(event_log,wmi,registry,files)
    else: 
        match_cmdline(event_log,wmi,registry)
    print("__________________________________Before Filtering__________________________________")
    for i in malware_instances:
        i.display()
        print("")
    for index, malware in enumerate(malware_instances):
        for proc in malware.process:
            if len(malware.process[proc][0]) != 0 and check_file(proc[1]) != 0: 
                if malware_instances[index] not in malware_instances_res: 
                    malware_instances_res.append(malware_instances[index])
    print("__________________________________After Filtering__________________________________")
    for i in malware_instances_res:
        i.display()
        print("")