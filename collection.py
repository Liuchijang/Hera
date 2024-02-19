import subprocess
import os
import re
import shutil
import json

def create_new_folder(baseFolder, newFoldername):
    folderPath = os.path.join(baseFolder,newFoldername)
    os.makedirs(folderPath,exist_ok=True)
    return folderPath
    
def create_new_file(filename, filepath, data):
    newfile = os.path.join(filepath,filename)
    try:
        with open(newfile,"w") as file:
            if isinstance(data, str):
                file.write(data)
            else:
                # If data is a list or tuple, write each element on a new line
                for line in data:
                    file.write(line + "\n")
            print(f"File '{newfile}' created successfully!")
    except IOError as e:
        print(f"Error creating file: {e}")

def Run_velociraptor_ls(accessor, filePath, verbose=False):
     # Path to executable of Velociraptor on Windows
    velociraptor_executable = r"velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'fs', '--accessor', accessor, 'ls', filePath]
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

def Run_velociraptor_query(query, verbose=False):
    # Path to executable of Velociraptor on Windows
    velociraptor_executable = r".\\velociraptor-v0.7.1-1-windows-amd64.exe"
    command = [velociraptor_executable, 'query', query, '--format', 'json']
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            print(f"\n----------------------------------------------------------------------------",f"Command: {command}",result.stdout,sep="\n")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

def extract_base_folder(path):
    components = path.split("\\")
    base_folder = components[:-1]
    return "/".join(base_folder)

def collect_evtx_file(outputFolder):
    system_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System\File"
    application_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\File"
    security_log_key_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security\File"
    output = Run_velociraptor_ls("reg",system_log_key_path, True)
    system_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    output = Run_velociraptor_ls("reg",application_log_key_path, True)
    application_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    output = Run_velociraptor_ls("reg",security_log_key_path, True)
    security_log_path = os.path.expandvars(eval(output)["Data"]["value"].lower())
    default_log_path = "C:/Windows/system32/winevt/logs"
    sourceFolderList = [default_log_path, extract_base_folder(system_log_path), extract_base_folder(application_log_path), extract_base_folder(security_log_path)]
    uniqueSourceFolderList = list(set(sourceFolderList))
    
    for i in uniqueSourceFolderList:
        query1 = f"SELECT Name, OSPath, Size as RawSize, humanize(bytes=Size) as Size, Mode.String, Mtime FROM glob(globs='{i}/*.evtx') "
        output = Run_velociraptor_query(query1,True)
        list_evtx_files= re.sub(r"\]\[", ",",output)
        parsed = json.loads(list_evtx_files)
        for j in parsed:
            source = re.sub(r"\\", "/", j["OSPath"])
            filename = j["Name"]
            dest = os.path.join(outputFolder,filename)
            query = f"SELECT copy(filename='{source}', accessor='ntfs', dest='{filename}') FROM scope()"
            Run_velociraptor_query(query)
            source = os.path.join(os.getcwd(),filename)
            shutil.move(source, dest)

cwd = os.getcwd()
extractFolder = create_new_folder(cwd, "extract")
collect_evtx_file(extractFolder)
