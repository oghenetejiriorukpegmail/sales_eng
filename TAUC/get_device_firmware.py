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

def get_device_firmware(deviceID):
    method = 'GET'
    request_url = f'/v1/openapi/device-information/device-info/{deviceID}'
    print(request_url)
    data = push_api(method, conn, request_url, payload, token)
    #print(data)
    firmware = data['result']['fwVersion']
    model = data['result']['deviceModel']
    type = data['result']['deviceCategory']
    return {'firmware':firmware, 'deviceModel': model, 'deviceType': type}

def get_device_id(sn, mac):
    method = 'GET'
    request_url = f'/v1/openapi/device-information/device-id?sn={sn}&mac={mac}'
    print(request_url)
    data = push_api(method, conn, request_url, payload, token)
    deviceID = data['result']['deviceId']
    return deviceID


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
payload = ''
client_secret = "6b42162e88a24e2bb0496ba7ccac72e3"
request_body = json.dumps(payload)
generate_signature.timestamp = str(int(time.time()))
generate_signature.nonce = str(uuid.uuid4())
generate_signature.key = client_secret
deviceTable = pd.DataFrame(columns=['DeviceID', 'SN', 'MAC', 'Firmware', 'Model', 'Device-Type'])

for status in network_status:
  dataList = []
  request_url = f"/v1/openapi/network-system-management/network-name-list/{status}?page=0&pageSize=10"
  print('API URL: ', request_url)
  method = 'GET'
  data = push_api(method, conn,request_url,payload, token)
  #print(data)
  dataList = data['result']['data']
networkDataList.extend(dataList)
#print('Network List:', networkDataList)
networkDataTable = list_to_table(networkDataList)
#print(networkDataTable)
#print(networkDataTable['id'])
for id in networkDataTable['id']:
   #print (id)
   networkInformation = get_network_data(id)
   #print(networkInformation, type(networkInformation))
   networkName = networkInformation['result']['network']['networkName']
   for device in networkInformation['result']['network']['meshUnitList']:
       deviceSN = device['sn']
       deviceMAC = device['mac']
       deviceID = device['deviceId']
       deviceInfo= get_device_firmware(deviceID)
       newTableDict = {'DeviceID': deviceID, 'SN': deviceSN, 'MAC': deviceMAC, 'Firmware': deviceInfo['firmware'], 'Model': deviceInfo['deviceModel'], 'Device-Type': deviceInfo['deviceType']}
       newTable = pd.DataFrame([newTableDict])
       deviceTable = pd.concat([deviceTable, newTable])

print(deviceTable)
deviceTable.to_excel('devfile.xlsx')
deco = deviceTable[deviceTable['Device-Type'] == 'DECO']
print(deco)
