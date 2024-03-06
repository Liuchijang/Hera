from typing import Union
from fastapi import FastAPI
import requests
app = FastAPI()
import os
import ipaddress


API_KEY = [
    "405f8e6b69f4df5fb3b7720788a3b41683c0e7322ff35028697bbbc4259263b5",
    "06426e167cb1dfa9f4d355464a5512625440883b1a0f9df59ae9430bceb3f38b",
    "4af70276e15f0efa24132b92f1c520d91b1de4dbac87d9c771c632d6a4a4e358",
    "624afaebdf55da27a0f5531881d33efa6b7c3b060b2f7a72044a1e082090f4ca",
    "e979f0d1b15693d631f569d1b06d08fec24a93d5d75bafd3bd3b4290568a489f",
    "39f5a0b76358a64d3f7771e353ebe5cd3e152a6c793eaa2fb09bc783307a11c6",
    "1880bbe1af52a6eaead6421193a939a7ee354322e9459ce92766c5607ba21e03",
    "9322fef94afbbb39f7ed20c41baae4718546c96f0f71ca0b9ec93f1e89d535f9",
    "f55c5c459ca58204126dae732a5ebda78e3244d0a1a408839a609bb60cb1c7e5",
    "2db6666777ccf86da690dd36049fa4e19593860d5ea9d22e4d45b0ba75d33864",
    "5e928558f3791f92aedf16ee0c973e4bfa01e17ef9435b75b88c97b6f181ba08",
    "b9214e9f8a7ee552588298a83ae73cc86ec2a75db4c2b4e992da0fc6ecf3da40",
    "ad823799a5e1d9347c26091144e9593088335c0c9dc16a7b0b4be6abd1387c26"
    ]
API_NUM = 0

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
