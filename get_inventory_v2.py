import http.client
import ssl
import json
import base64
import hashlib
import hmac
import time
import uuid
import generate_signature
import test_signature
import pandas as pd




def list_to_table(list_of_dict):
    dataTable = pd.DataFrame(list_of_dict)
    return dataTable

# Define the paths to your certificate and key files
cert_file_path = 'certs/client.crt'
key_file_path = 'certs/client.key'
token_file_path = open('bearer_token', 'r')

# Create an SSL context
context = ssl.create_default_context()

# Load the client certificate and key
context.load_cert_chain(cert_file_path, key_file_path)  # Using positional arguments

conn = http.client.HTTPSConnection("use1-tauc-openapi.tplinkcloud.com", context=context)
token =token_file_path.read()

network_status = ['ONLINE', 'OFFLINE', 'ABNORMAL', 'INVENTORY', 'NAT-LOCKED']
networkDataList = []
#payload = '{"networkName":"EX920","username":".","meshUnitList":[{"sn":"Y234081000803","mac":"5C628BA23548"}]}'
payload = ''
client_secret = "6b42162e88a24e2bb0496ba7ccac72e3"
#request_url = "https://use1-tauc-openapi.tplinkcloud.com/v1/openapi/service-activation-services/network"
#request_url = "/v1/openapi/network-system-management/name"
#request_url = "/v1/openapi/inventory-management/all-inventory?page=0&pageSize=10"
#request_url = "/v1/openapi/inventory-management/inactive-inventory?page=0&pageSize=10"
#request_url = "/v1/openapi/network-system-management/network-name-list/ONLINE?page=0&pageSize=10"
request_body = json.dumps(payload)
#print (request_body)
#generate_signature.timestamp = str(int(time.time()))
#generate_signature.nonce = str(uuid.uuid4())
#generate_signature.key = client_secret
test_signature.timestamp = str(int(time.time()))
test_signature.nonce = str(uuid.uuid4())
test_signature.key = client_secret

for status in network_status:
  dataList = []
  request_url = "/v1/openapi/network-system-management/network-name-list/"+status+"?page=0&pageSize=10"
  print('API URL: ', request_url)
  headers = {
  'Content-Type': 'application/json',
  'Authorization': 'Bearer '+token,
  #'X-Authorization': generate_signature.get_oauth_two_x_authorization(client_secret, request_url=request_url)
  'X-Authorization': 'Nonce='+test_signature.nonce+',Signature='+test_signature.generate_signature(url=request_url,content=payload)+',Timestamp='+test_signature.timestamp
  }
  #print(headers,'\r')
  conn.request("GET", request_url, request_body, headers)
  res = conn.getresponse()
  data = res.read()
  print(data)
  data_dict = json.loads(data.decode("utf-8"))
  #print(data_dict)
  dataList = data_dict['result']['data']
  if dataList != []:
    networkDataList.extend(dataList)
print('Network List:', networkDataList)
networkDataTable = list_to_table(networkDataList)
print(networkDataTable)