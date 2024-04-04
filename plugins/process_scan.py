from core.velociraptor_sever_api import Run_velociraptor_query


def process_module( verbose=False):
    print("+"*50 + "\nProcesses scanning...")
    artifact = "Windows.Memory.LocalHollowsHunter"
    query = "select * from Artifact.{}()".format(artifact)
    Run_velociraptor_query(query)
    with open(r".\\output\\HollowsHunter\\summary.json","r") as file:
        output = file.read()
        parsedOutput = eval(output)
        print("Process Scan time:",parsedOutput['scan_date_time'],
              "\nTotal scan time in ms:",parsedOutput['scan_time_ms'],
              "\nTotal scanned processes:",parsedOutput['scanned_count'],
              "\nSuspicious process count:",parsedOutput['suspicious_count'])
        if verbose:
            print("+++++++++++++ Suspicious processes infomartion +++++++++++++")
            for suspicious in parsedOutput['suspicious']:
                with open(rf".\output\HollowsHunter\process_{suspicious['pid']}\scan_report.json") as proc:
                    data = eval(proc.read())
                    for i in data['scans']:
                        for j in i.keys():
                            if 'module_file' in i[j]:
                                if i[j]['module_file'].replace("\\","").lower() == "C:\\Windows\\System32\\ntdll.dll".replace("\\","").lower(): continue
                                print("Process ID:",suspicious['pid'])
                                print("Process Name:",suspicious['name'])
                                print("Image Fullpath:",data['main_image_path'])
                                print(f"Suspicious Module (Triggered by {j}):",i[j]['module_file'])
                proc.close()
                print("")
        print("Scan process completed")
    file.close()
    return parsedOutput



if __name__ == "__main__":
    process_module()
