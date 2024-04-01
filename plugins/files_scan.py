import os
import re
import json
from core.velociraptor_sever_api import Run_velociraptor_query
from core.check_virustotal import *

def fileScan_module(outputFolder, verbose=False,save_to_file=False):
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nFiles scanning...")
    artifact = "Files.scan"
    query = "select * from Artifact.{}()".format(artifact)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    result = []
    if check_connect():
        for i in parsed:
            #whitelisting known legit executable
            if i['MD5'] == "eaec6dadcb123b00ea52655510d0b4d6": continue
            check = check_virustotal("check_hash", i['MD5'])
            if check == 1:
                if verbose: print("Detected malicious file, FilePath: " + i['OSPath'])
                result.append(i)
    else:
        with open("./data/malicious_MD5.txt", "r") as f:
            malicious_MD5 = set(line.strip() for line in f)
        for i in parsed:
            if i['MD5'] == "eaec6dadcb123b00ea52655510d0b4d6": continue
            if i['MD5'] in malicious_MD5:
                if verbose: print("Detected malicious file, FilePath: " + i['OSPath'])
                result.append(i)
    if save_to_file:
        filepath = os.path.join(outputFolder,"Files_module.json")
        with open(filepath, 'w') as f:
            json.dump(result,f,indent=4)
            print(f"Saved file module output at {filepath}")
    print("Scan Files completed.")
    return result

def check_file(file):
    # file=C:\\Windows\\explorer.exe
    query = "SELECT OSPath, Name, hash(path=OSPath, hashselect='MD5').MD5 as MD5, authenticode(filename=OSPath).Trusted as Trust FROM glob(globs='{}')".format(file)
    output = Run_velociraptor_query(query)
    correctSyntax = re.sub(r"\]\[", ",",output)
    parsed = eval(correctSyntax)
    if check_connect():
        #whitelisting known legit executable
        if parsed['MD5'] == "eaec6dadcb123b00ea52655510d0b4d6": return 0
        check = check_virustotal("check_hash", parsed['MD5'])
        if check == 1:
            return 1
    else:
        with open("./data/malicious_MD5.txt", "r") as f:
            malicious_MD5 = set(line.strip() for line in f)
        if parsed['MD5'] == "eaec6dadcb123b00ea52655510d0b4d6": return 0
        if parsed['MD5'] in malicious_MD5:
            return 1
    

if __name__ == "__main__":
    fileScan_module()
