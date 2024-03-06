import requests
# mode: check_hash | check_ip
def check_virustotal(mode, value):
    api_url = f'https://fastapivirustotal-production.up.railway.app/{mode}/{value}'
    response = requests.get(api_url)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return 0
