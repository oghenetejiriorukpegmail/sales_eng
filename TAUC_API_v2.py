import http.client
import ssl
import json
import time
import uuid
import re
import get_bearer_tokens
import generate_signature

def normalize_mac(mac):
    # Check if the MAC address is already in the correct format
    if re.match(r'^[0-9a-fA-F]{12}$', mac):
        return mac.upper()
    # Remove any delimiters (., :, -) and convert to lowercase
    normalized_mac = re.sub(r'[-:]', '', mac).upper()
    return normalized_mac

def generate_headers(token, request_url, payload):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'X-Authorization': f'Nonce={generate_signature.nonce},Signature={generate_signature.generate_signature(url=request_url, content=payload)},Timestamp={generate_signature.timestamp}'
    }
    print(headers)
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
    data = json.loads(res.read())
    print(data)
    if data['errorCode'] != 0:
        print('Message:',data['msg'],'\n', data['result'])
        exit()
    else:
        return data

def main():
    cert_file_path = 'certs/client.crt'
    key_file_path = 'certs/client.key'
    token_file_path = 'bearer_token'
    token = get_token(token_file_path)
    context = create_ssl_context(cert_file_path, key_file_path)
    sn = input ('Insert Serial Number["Y234081000803"]:')
    mac = input ('Insert Mac Address["5C628BA23548"]:')
    client_secret = "6b42162e88a24e2bb0496ba7ccac72e3"
    generate_signature.timestamp = str(int(time.time()))
    generate_signature.nonce = str(uuid.uuid4())
    generate_signature.key = client_secret
    operation = input('Choose Your Operation[Add, Remove]:')

    conn = http.client.HTTPSConnection("use1-tauc-openapi.tplinkcloud.com", context=context)
    
    token = get_bearer_tokens.get_bearer_tokens()

    if operation.lower() == 'add':
        #Create Network
        request_url = "/v1/openapi/service-activation-services/network"
        payload = f'{{"networkName":"EX920","username":".","meshUnitList":[{{"sn":"{sn}","mac":"{mac}"}}]}}'
        #print(payload)
        method = "POST"
        response = push_api(method, conn, request_url, payload, token )
        #print(response)

        request_url = f"/v1/openapi/network-system-management/name?mac={mac}&sn={sn}"
        payload = ""
        method = "GET"
        response = push_api(method, conn, request_url, payload, token)
        #print(response)
    if operation.lower() == 'remove':
        request_url = f"/v1/openapi/network-system-management/name?mac={mac}&sn={sn}"
        payload = ""
        method = "GET"
        response = push_api(method, conn, request_url, payload, token)
        deviceID = response['result']['id']
        request_url = f"/v1/openapi/network-system-management/network/{deviceID}"
        payload = ""
        method = "DELETE"
        response = push_api(method, conn, request_url, payload, token)
        #print(response)        

if __name__ == "__main__":
    main()