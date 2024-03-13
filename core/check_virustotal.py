import requests
# mode: check_hash | check_ip
def check_virustotal(mode, value):
    api_url = f'https://fastapivirustotal-production.up.railway.app/{mode}/{value}'
    response = requests.get(api_url)

    if response.status_code == 200:
        return int(response.json().split()[1])
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return 0

def check_connect():
    url = "https://fastapivirustotal-production.up.railway.app"
    try:
      response = requests.get(url)
      response.raise_for_status()  # Raise an exception for non-2xx status codes
      return True
    except requests.exceptions.RequestException as e:
      print("Can not connented to internet!\nPlease check the internet conection.\n\n")
      return False
