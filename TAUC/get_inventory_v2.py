import http.client
import ssl
import json
import time
import uuid
import generate_signature
import pandas as pd
import sys




def list_to_table(list_of_dict):
    dataTable = pd.DataFrame(list_of_dict)
    return dataTable

def make_pretty_json(json_data):
    return json.dumps(json_data, indent=1)

def generate_headers(token, request_url, payload):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'X-Authorization': f'Nonce={generate_signature.nonce},Signature={generate_signature.generate_signature(url=request_url, content=payload)},Timestamp={generate_signature.timestamp}'
    }
    #print(headers)
    return headers

def create_ssl_context(cert_file_path, key_file_path):
    context = ssl.create_default_context()
    context.load_cert_chain(cert_file_path, key_file_path)
    return context

def get_token(token_file_path):
    with open(token_file_path, 'r') as file:
        return file.read().strip()

def push_api(method, conn,request_url,payload, token):
    conn.request(method, request_url, payload, generate_headers(token, request_url, payload))
    res = conn.getresponse()
    response = res.read()
    #print(response)
    data = json.loads(response)
    #print(make_pretty_json(data))
    #print(int(data['errorCode']) == 0)
    if int(data['errorCode']) == 0:
        return data
    else:
        print('Message:',data['msg'],'\n', make_pretty_json(data['result']))
        exit()

def get_network_data(networkId):
    method = 'GET'
    request_url = f'/v1/openapi/network-system-management/details/{networkId}'
    data = push_api(method, conn, request_url, payload, token)
    return data

def get_device_info(deviceID):
    method = 'GET'
    request_url = f'/v1/openapi/device-information/device-info/{deviceID}'
    payload = ''
    print(request_url)
    data = push_api(method, conn, request_url, payload, token)
    print(data)



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

network_status = ['ONLINE', 'OFFLINE', 'ABNORMAL', 'INVENTORY', 'NAT-LOCKED', 'SUSPEND']
client_secret = "6b42162e88a24e2bb0496ba7ccac72e3"
generate_signature.timestamp = str(int(time.time()))
generate_signature.nonce = str(uuid.uuid4())
generate_signature.key = client_secret

for status in network_status:
    request_url = f"/v1/openapi/network-system-management/network-name-list?page=0&pageSize=100&networkStatus={status}"
    print('API URL: ', request_url)
    method = 'GET'
    payload = ''
    data = push_api(method, conn,request_url,payload, token)
    #print(data)
    dataList = data['result']['data']
    print(dataList)
