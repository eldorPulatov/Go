import requests

url = "http://localhost:8080/get-tokens?user_id=1"

response = requests.get(url)

print(response.text)