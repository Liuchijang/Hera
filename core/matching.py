from malware import *
import json
from collections import defaultdict


malware_instance = Malware()

result = []
filepath = ".\\output\\event-log-module-output.jsonl"
with open(filepath,"r") as file:
    for line in file:
        result.append(json.loads(line))

def process_tree():
    lst = []
    for i in result:
        if i['EventID'] == 4688:
            lst.append(i)

    # print(result[0]['Timestamp'])
    pid_to_ppid = defaultdict(list)
    pid_to_cmd = defaultdict(list)
    ppid_to_name = defaultdict(list)

    # Đổ dữ liệu từ danh sách vào defaultdict
    for item in lst:
        pid = item['Details']['PID']
        ppid = item['ExtraFieldInfo']['ProcessId']
        cmd = item['Details']['Cmdline']
        pid_to_ppid[ppid].append(pid)
        pid_to_cmd[pid] = cmd
        if 'ExtraFieldInfo' in item and 'ParentProcessName' in item['ExtraFieldInfo']:
            ppid_to_name[ppid] = item['ExtraFieldInfo']['ParentProcessName']
        else: ppid_to_name[ppid] = ""

    # Hiển thị cây quan hệ giữa PID và ProcessId
    def display_tree(ppid, pid_dict, prefix='', is_first=True, is_last=True):
        pid_dict[ppid] = pid_to_cmd[ppid]   
        if is_last and is_first:
            print(prefix + '└── ' + f"{ppid} - {ppid_to_name[ppid]}")
        elif is_last and not is_first:
            print(prefix + '└── ' + f"{ppid} - {pid_to_cmd[ppid]}")    
        else:
            print(prefix + '├── ' + f"{ppid} - {pid_to_cmd[ppid]}")
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
        return pid_dict