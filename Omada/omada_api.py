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
        #endpoint = f"/{omada_id}/openapi/login?client_id={client_id}&omadac_id={omada_id}"
        #endpoint = f"/{omada_id}/openapi/authorize/login?client_id={client_id}&omadac_id={omada_id}"
        #endpoint = f"/{omada_id}/openapi/authorize/login?client_id={client_id}&omadac_id={omada_id}"
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

def get_users(omada_id, accessToken):
    method = "GET"
    request_url = f"/openapi/v1/{omada_id}/users?page=1&pageSize=20"
    payload = ""
    userdata = send_api_call(accessToken, request_url, method, payload)
    userList = userdata['data']
    #print(make_pretty_json(userList))
    usersTable = pd.DataFrame.from_dict(userList)[['name', 'id', 'roleId', 'email']]
    return usersTable
    
def create_user(omada_id, accessToken, userPayload, username):
    userData = get_users(omada_id, accessToken)
    #print(userData)
    if username in str(userData):
        print('User already present on Controller!!!')
    else:
        method = "POST"
        request_url = f"/openapi/v1/{omada_id}/users"
        #print(method, request_url, userPayload, sep='\n')
        send_api_call(accessToken, request_url, method, userPayload)
        usersTable = get_users(omada_id, accessToken)
        print(usersTable)
        return (usersTable)

def get_sites(omada_id, accessToken):
    method = "GET"
    request_url = f"/openapi/v1/{omada_id}/sites?page=1&pageSize=20"
    payload = ""
    siteData = send_api_call(accessToken, request_url, method, payload)
    sitesList = siteData['data']
    print(make_pretty_json(sitesList))
    return pd.DataFrame.from_dict(sitesList)[['name', 'siteId']]

def get_site_id(omada_id, accessToken, siteName):
    method = "GET"
    request_url = f"/openapi/v1/{omada_id}/sites?page=1&pageSize=20"
    payload = ""
    siteData = send_api_call(accessToken, request_url, method, payload)
    sitesList = siteData['data']
    for site in sitesList:
        if site['name'] == siteName:
            return site['siteId']
    print('Site Not Found!!!')
    

def get_vlans(omada_id, accessToken, siteID):
    method = "GET"
    request_url = f"/openapi/v1/{omada_id}/sites/{siteID}/lan-networks?page=1&pageSize=20"
    payload = ""
    vlanData = send_api_call(accessToken, request_url, method, payload)
    vlanList = vlanData['data']
    #print(make_pretty_json(userList))
    return vlanList


def create_vlan(omada_id, accessToken, siteID, vlanBody, vlanName, vlanID):
    vlanData = get_vlans(omada_id, accessToken, siteID)
    if vlanName == str(vlanData):
        print( f'This VLAN {vlanName} with VLAN ID: {vlanID} is already present!!!')
    else:
        method = "POST"
        request_url = f"/openapi/v1/{omada_id}/sites/{siteID}/lan-networks"
        payload = vlanBody
        vlanData = send_api_call(accessToken, request_url, method, payload)
        vlanList = vlanData['data']
        return (vlanList)

# Declare Variables
# Extract Omada information from yaml file
omadaData = yaml2json('Omada/omada.yaml')
#omadaData = yaml2json('Omada/omada_local.yaml')
omada_server = omadaData['omada']['server']
#omada_api_server = omadaData['omada']['api_server']
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
    users = get_users(omada_id, accessToken)
    print(users)
    
    usersList = omadaData['users']
    #print(usersList)
    for users in usersList:
        name = users['username']
        userPassword = users['password']
        email = users['email']
        userType = users['administrator_type']
        userRole = users['role']
        alerts = users['alert_emails']
        notification = users['alert_emails']
        allsites = users['allSitePrevileges']

        userBody = {
            "type": userType,
            "roleId": userRole,
            "name": name,
            "password": userPassword,
            "email": email,
            "alert": True,
            "allSite": True,
            "verified": False,
            "userLevel": 0
            }
        #print('userbody=',userBody)
        create_user(omada_id,accessToken, json.dumps(userBody), name)
    
    siteTable = get_sites(omada_id, accessToken)
    print(siteTable)

    
    siteName = 'Mobile'
    siteID = get_site_id(omada_id, accessToken, siteName)
    print(siteID)

    get_vlans(omada_id, accessToken, siteID)

    vlanList = omadaData['Wired_Networks']['LAN']
    print(vlanList)

    for vlan in vlanList:
        vlanName = vlan['name']
        vlanID = vlan['id']
        vlanType = vlan['purpose']
        vlanGatewayInterfaces = vlan['LANInterfaces']
        vlanGatewayIP = vlan['gateway']
        enableDHCP = vlan['DHCPServer']
        DHCPStart = vlan['DHCPStart']
        DHCPEnd = vlan['DHCPEnd']
        DNSServer = vlan['DNSServer']


    vlanBody = {
        "name": vlanName,
        "purpose": vlanType,
        "interfaceIds": [vlanGatewayInterfaces],
        "vlanType": 0,
        "vlans": "",
        "vlan": 0,
        "application": 0,
        "gatewaySubnet": "",
        "dhcpSettingsVO": {
            "enable": enableDHCP,
            "ipRangePool": [
            {
                "ipaddrStart": DHCPStart,
                "ipaddrEnd": DHCPEnd
            }
            ],
            "dhcpns": "",
            "priDns": "",
            "sndDns": "",
            "leasetime": 0,
            "gateway": vlanGatewayIP,
         },
        "allLan": True
        }
    print(vlanBody)
    vlanData = create_vlan(omada_id, accessToken, siteID, vlanBody, vlanName, vlanID)
    print(vlanData)

if __name__ == "__main__":
    main()
       