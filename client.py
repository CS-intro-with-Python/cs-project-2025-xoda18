import requests

url = "http://localhost:8080/hello"


response = requests.get(url)

if response.status_code == 200:
    print("ok")
    exit(0)
else:
    print(f"not ok, status = {response.status_code}")
    exit(1)