from typing import Union
from fastapi import FastAPI
import requests
app = FastAPI()
import os
import ipaddress


API_KEY = [
    "Nothing here"
    ]
API_NUM = 0
@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/check_ip/{ip}")
def check_ip(ip: str): 
    if not is_valid_ip(ip):
        return ip + " is not a valid IP address"
    if not os.path.isfile("ipscanned.txt"):
        open("ipscanned.txt", "w").close()

    with open("ipscanned.txt", "r") as file:
        for line in file:
            if line.split(":")[0] == ip:
                return line.strip()
            else:
                continue

    global API_NUM
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
    url = VIRUSTOTAL_API_URL + ip
    headers = {"x-apikey": API_KEY[API_NUM],
               "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 400: # IP address is not a valid IP address
        return "IP " + ip + " is not a valid IP address" 
    elif response.status_code == 401: # API KEY is being limited
        if API_NUM == len(API_KEY):
            API_NUM = 0
            return check_ip(ip)
        if API_NUM != 0:
            API_NUM = API_NUM + 1
            return check_ip(ip)
    else:
        response = response.json()
        malicious = response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        if malicious > 0:
            with open("ipscanned.txt", "a") as file:
                file.write(ip + ": Malicious\n")
            return ip + ": Malicious"
        elif suspicious > 0:
            with open("ipscanned.txt", "a") as file:
                file.write(ip + ": Suspicious\n")
            return ip + ": Suspicious"
        else:
            with open("ipscanned.txt", "a") as file:
                file.write(ip + ": Safe\n")
            return ip + ": Safe"

@app.get("/check_hash/{hash}")
def check_hash(hash: str):
    if not os.path.isfile("hashscanned.txt"):
        open("hashscanned.txt", "w").close()

    with open("hashscanned.txt", "r") as file:
        for line in file:
            if line.split(":")[0] == hash:
                return line.strip()
            else:
                continue

    global API_NUM
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
    url = VIRUSTOTAL_API_URL + hash
    headers = {"x-apikey": API_KEY[API_NUM],
                "Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 400: # Hash is not a valid hash or not found
        return "Hash " + hash + " is not a valid hash"
    elif response.status_code == 404: # Hash is not found
        return "Hash " + hash + " is not found"
    elif response.status_code == 401: # API KEY is being limited
        if API_NUM == len(API_KEY):
            API_NUM = 0
            return check_hash(hash)
        if API_NUM != 0:
            API_NUM = API_NUM + 1
            return check_hash(hash)
    else:
        response = response.json()
        malicious = response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = response["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        if malicious > 0:
            with open("hashscanned.txt", "a") as file:
                file.write(hash + ": Malicious\n")
            return hash + ": Malicious"
        elif suspicious > 0:
            with open("hashscanned.txt", "a") as file:
                file.write(hash + ": Suspicious\n")
            return hash + ": Suspicious"
        else:
            with open("hashscanned.txt", "a") as file:
                file.write(hash + ": Safe\n")
            return hash + ": Safe" 

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
