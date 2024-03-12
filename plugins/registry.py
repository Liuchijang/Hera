import os
import re
from core.velociraptor_sever_api import Run_velociraptor_query



def get_registry_yaml_files(folder_path):
    registry_yaml_files = []
    for filename in os.listdir(folder_path):
        if filename.startswith("Registry.") and filename.endswith(".yaml"):
            # Loại bỏ đuôi file (.yaml) và thêm tên file vào mảng
            registry_yaml_files.append(filename[:-5])

    return registry_yaml_files

folder_path = ".//data//artifacts"
artifacts = get_registry_yaml_files(folder_path)


def registry_module():
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nRegistry scanning...")
    query = ""
    data = []
    for artifact in artifacts:
        query = "select * from Artifact.{}()".format(artifact)
        output = Run_velociraptor_query(query)
        correctSyntax = re.sub(r"\]\[", ",",output)
        parsed = eval(correctSyntax)
        data.extend(parsed)
    for i in data:
        print("Path: " + i['ValueName'] + "\n" + "Value:" + str(i['Contents']) + "\n")


if __name__ == "__main__":
    registry_module()

