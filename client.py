from http.client import responses

import requests

url = "http://localhost:8080/hello"


response = requests.get(url)

if response.status_code == 200:
    print("ok")
else:
    print("not ok")
