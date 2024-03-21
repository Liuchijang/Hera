from malware import *
import json
from collections import defaultdict


malware_instances = []

event_log = []
filepath = ".\\output\\event-log-module-output.jsonl"
with open(filepath,"r") as file:
    for line in file:
        event_log.append(json.loads(line))

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
    pid_to_cmd[(pid, lid)] = (cmd, lid)
    pid_to_name[(pid, lid)] = (item['Details']['Proc'], lid)
    if 'ExtraFieldInfo' in item and 'ParentProcessName' in item['ExtraFieldInfo']:
        ppid_to_name[(ppid, lid)] = (item['ExtraFieldInfo']['ParentProcessName'], lid)
    else: ppid_to_name[(ppid, lid)] = ("", lid)
matched_wmi_instances = []
matched_log_records = []
matched_connections = []
matched_processes = []

def event_id_8(event_log):
    result = []
    for i in event_log:
        if i['EventID'] == 8 and ('hollows_hunter64.exe' not in i['Details']['SrcProc']):
            tmp = (i['Details']['SrcPID'], i['Details'][''], i['Details']['TgtPID'], i['Details']['TgtProc'])
            result.append(tmp)
    return result

def event_id_13(event_log):
    result = []
    for i in event_log:
        if i['EventID'] == 13:
            tmp = (i['Details']['PID'], i['Details']['Proc'], i['Details']['TgtObj'], i['Details'][''])
            result.append(tmp)
    return result


def create_process_tree():
    # Hiển thị cây quan hệ giữa PID và ProcessId
    def display_tree(ppid, pid_dict, prefix='', is_first=True, is_last=True):
        pid_dict[ppid] = pid_to_cmd[ppid]   
        if is_last and is_first:
            print()
            print(prefix + '└── ' + f"{ppid[0]} - {ppid_to_name[ppid][0]}")
        elif is_last and not is_first:
            print(prefix + '└── ' + f"{ppid[0]} - {pid_to_cmd[ppid][0]}")    
        else:
            print(prefix + '├── ' + f"{ppid[0]} - {pid_to_cmd[ppid][0]}")
        children = pid_to_ppid.get(ppid, [])
        count = len(children)
        for i, child_pid in enumerate(children, 1):
            is_first = False
            is_last = i == count
            display_tree(child_pid, pid_dict , prefix + ('    ' if is_last else '│   '), False, is_last)
            
    # Tạo một tập hợp duy nhất của tất cả các phần tử từ tập hợp các giá trị
    all_ppids = set(pid for sublist in pid_to_ppid.values() for pid in sublist)

    # Tìm PPID gốc (PPID không phải là PID của bất kỳ tiến trình nào)
    root_ppids = set(pid_to_ppid.keys()) - all_ppids
    for root_pid in root_ppids:
        pid_dict = {}
        display_tree(root_pid, pid_dict)
        process_tree.append(pid_dict)
    return process_tree

def match_cmdline(wmi, network, event_log):
    for i in wmi:
        for j in event_log:
            # Matching based on event log id 5861/1-4688/20 respectively
            if ("Details" in j['Details'] and i['Arguments'].replace("\\","") in j['Details']['Details'].replace("\\",""))  \
                or ("Cmdline" in j['Details'] and i['Arguments'].replace("\\","") == j['Details']['Cmdline'].replace("\\","")) \
                or ("Tgt" in j['Details'] and i['Arguments'].replace("\\","") == j['Details']['Tgt'].replace("\\","").replace("\"","")):
                if i not in matched_wmi_instances: matched_wmi_instances.append(i)
                if j not in matched_log_records: matched_log_records.append(j)
        for k in network:
            if k['CommandLine'].replace("\"","").replace("\\","") in i['Arguments'].replace("\"","").replace("\\",""):
                if i not in matched_wmi_instances: matched_wmi_instances.append(i)
                if k not in matched_connections: matched_connections.append(k)
    for i in event_log:
        for j in network:
            if "Cmdline" in i['Details'] and j['CommandLine'].replace("\"","").replace("\\","") in 	i['Details']['Cmdline'].replace("\"","").replace("\\",""):
                if i not in matched_log_records: matched_log_records.append(i)
                if k not in matched_connections: matched_connections.append(j)

def match_loaded_dll(event_log, network, process):
    for sus in process['suspicious']:
        with open(rf".\output\HollowsHunter\process_{sus['pid']}\scan_report.json") as proc:
            data = eval(proc.read())
            for i in data['scans']:
                for j in i.keys():
                    if 'module_file' in i[j]\
                        and i[j]['module_file'].replace("\\","").lower() != "C:\Windows\System32\\ntdll.dll".replace("\\","").lower():
                        for k in event_log:
                            if ('Rule' in k['Details'] \
                                and k['Details']['Rule'] == 'DLL'  \
                                and i[j]['module_file'].replace("\\","").lower() == k['Details']['Path'].replace("\\","").lower()):
                                matched_log_records.append(k)
                                matched_processes.append(sus)
                        for n in network:
                            for m in n['ModulePath']:
                                if i[j]['module_file'].replace("\\","").lower() == m.replace("\\","").lower():
                                    matched_connections.append(n)
                                    matched_processes.append(sus)
            proc.close()
    for i in event_log:
        for j in network:
            for k in j['ModulePath']:
                ## Matching based on event log id 11
                if ('Rule' in i['Details'] \
                    and i['Details']['Rule'] == 'DLL'  \
                    and i['Details']['Proc'].split("\\")[-1].lower() == j['Name'].lower()\
                    and k.replace("\\","").lower() == i['Details']['Path'].replace("\\","").lower()):
                    matched_log_records.append(i)
                    matched_connections.append(j)

def creat_object(process_tree):
    for i in process_tree:
        malware_instances.append(Malware(i))

def matching(process, registry, files, network, wmi):
    print(process)
    print(registry)
    print(files)
    print(network)
    print(wmi)
    creat_object(create_process_tree())

if __name__ == "__main__":
    # for i in malware_instances:
    #     print(i.process)
    tmp = event_id_13(event_log)
    for i in tmp:
        print(i)
    print("Done")