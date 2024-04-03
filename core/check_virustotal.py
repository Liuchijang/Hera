import requests
# mode: check_hash | check_ip
def check_virustotal(mode, value):
    api_url = f'https://fastapivirustotal-production.up.railway.app/{mode}/{value}'
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            return int(response.json().split()[1])
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return 0
    except requests.exceptions.Timeout:
        print(f"Timeout occurred while connecting to the server when check value ({value})")
        return 0
    except requests.exceptions.RequestException as e:
        print(f"An error occurred when check value ({value}): {e}")
        return 0

def check_connect():
    url = "https://fastapivirustotal-production.up.railway.app"
    try:
      response = requests.get(url, timeout=5)
      response.raise_for_status()  # Raise an exception for non-2xx status codes
      return True
    except requests.exceptions.Timeout:
        print("Timeout occurred while connecting to the server.\n\n")
        return False
    except requests.exceptions.RequestException as e:
      print("Can not connect to internet!\nPlease check your Internet connection.\n\n")
      return False
