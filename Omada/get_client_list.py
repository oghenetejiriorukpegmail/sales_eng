import http.client
import json
import yaml
import ssl
import pandas as pd
import traceback

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


# Convert yaml to json
def yaml2json(yamlFileName):
    with open(yamlFileName, 'r') as yamlFile:
        data = yaml.safe_load(yamlFile)
        #print (data)
    jsonData = json.loads(json.dumps(data))
    return jsonData

def make_pretty_json(json_data):
    return json.dumps(json_data, indent=1)

# Log into Omada Server
def login_to_api(omada_server, omada_port, omada_id, client_id, username, password):

    try:
        conn = http.client.HTTPSConnection(omada_server, port=omada_port, context=context)
        headers = {"Content-Type": "application/json"}
        payload = {
            "username": username,
            "password": password
        }
        payload_json = json.dumps(payload)

        endpoint = f"/openapi/authorize/login?client_id={client_id}&omadac_id={omada_id}"
        print(endpoint)
        conn.request("POST", endpoint, body=payload_json, headers=headers)
        response = conn.getresponse()
        #print(response.read())
        data = json.loads(response.read())
        print(data)

        if response.status == 200:
            # Handle successful login (e.g., store tokens, session info, etc.)
            print("Login successful!")
            csrfToken = data['result']['csrfToken']
            sessionId = data['result']['sessionId']
            return csrfToken, sessionId
    

        else:
            print(f"Error: {response.status} {response.reason}")
    except Exception as e:
        print(f"Error making API request: {e}")
        print(traceback.format_exc())

    finally:
        conn.close()

# Get Authorization Code
def get_code(omada_server, omada_port, client_id, omada_id, csrf_token, session_id):
    #print (csrf_token,client_id,omada_id)
    try:
        conn = http.client.HTTPSConnection(omada_server, port=omada_port, context=context)
        headers = {
        'Csrf-Token': csrf_token,
        'Cookie': f'TPOMADA_SESSIONID={session_id}',
        'Content-Type': 'application/json'
        }

        conn.request("POST", f"/openapi/authorize/code?response_type=code&client_id={client_id}&omadac_id={omada_id}", body="", headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        #print(data)
        if response.status == 200:
          if data['errorCode'] == 0:
              code = data['result']
              #print(code)
              return code

          else:
              print('Encountered an error:', data)

    except Exception as e:
        print(f"Error making API request: {e}")
        return None
    finally:
        conn.close()    

# Get Authentication Token
def get_access_token(omada_server, omada_port, code, client_id, client_secret):
    print ('Code:', code)
    try:
        conn = http.client.HTTPSConnection(omada_server, port=omada_port, context=context)
        headers = {"Content-Type": "application/json"}
        payload = {
            "client_id": client_id,
            "client_secret": client_secret
        }
        payload_json = json.dumps(payload)

        conn.request("POST", f"/openapi/authorize/token?code={code}&grant_type=authorization_code", body=payload_json, headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        #print(data)

        if response.status == 200:
            if data['errorCode'] == 0:
              access_token = data['result']["accessToken"]
              return access_token
            else:
                print('Encountered an error', data)
        else:
            print(f"Error: {response.status} {response.reason}")
            return None
    except Exception as e:
        print(f"Error making API request: {e}")
        return None
    finally:
        conn.close()


def send_api_call(accessToken, request_url, method, payload):
    #print(request_url)
    try:
        conn = http.client.HTTPSConnection(omada_server, port=omada_port, context=context)
        headers = { "Authorization": f"AccessToken={accessToken}", "Content-Type": "application/json"}
        #print(headers)
        conn.request(method, request_url, body=payload, headers=headers )
        data = json.loads(conn.getresponse().read())
        #print(data)
        if data['errorCode'] != 0:
            quit()
        else:
            return data['result']

    except Exception as e:
      print(f"Error making API request: {e}")
      print(traceback.format_exc())
      return None
    finally:
        conn.close()

 
def get_site_id(omada_id, accessToken, siteName):
    method = "GET"
    request_url = f"/openapi/v1/{omada_id}/sites?page=1&pageSize=20"
    payload = ""
    siteData = send_api_call(accessToken, request_url, method, payload)
    sitesList = siteData['data']
    #print(sitesList)
    for site in sitesList:
        if site['name'] == siteName:
            #print(site['siteId'])
            return site['siteId']
    print('Site Not Found!!!')
    

def get_clients(omada_id, accessToken, siteName):
    method = "GET"
    siteId = get_site_id(omada_id, accessToken, siteName)
    #print(siteId)
    request_url = f"/openapi/v1/{omada_id}/sites/{siteId}/clients?page=1&pageSize=20"
    payload = ""
    clientData = send_api_call(accessToken, request_url, method, payload)
    print(clientData)
    clientList = clientData['data']
    return clientList



# Declare Variables
# Extract Omada information from yaml file
omadaData = yaml2json('Omada/get_client_list.yaml')
omada_server = omadaData['omada']['server']
omada_port = omadaData['omada']['port']
omada_id = omadaData['omada']['omadaID']
client_id = omadaData['omada']['clientID']
client_secret = omadaData['omada']['clientSecret']
username = omadaData['omada']['userName']
password = omadaData['omada']['userPassword']


def main():
    print(omada_server, omada_port, omada_id)
    (crsfToken, sessionId) = login_to_api(omada_server, omada_port, omada_id, client_id, username, password)
    print('CRSF-Token: ',crsfToken, 'Session ID: ', sessionId)
    code = get_code(omada_server, omada_port, client_id, omada_id, crsfToken, sessionId)
    print('Authorization Code:', code)
    accessToken = get_access_token(omada_server, omada_port, code, client_id=client_id, client_secret=client_secret)
    print('Access Token:', accessToken)


    siteList = omadaData['sites']
    for site in siteList:
        #print(site)
        clientList = get_clients(omada_id, accessToken, site)
        print(make_pretty_json(clientList))
        clientTable = pd.DataFrame(clientList, columns=['name','hostName','deviceType','ip','networkName','wireless','ssid', 'switchName', 'apName'])
        print(clientTable)

    


if __name__ == "__main__":
    main()
       