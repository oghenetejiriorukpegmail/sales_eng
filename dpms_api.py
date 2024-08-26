import http.client
import json
import yaml
import ssl

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


# Log into DPMS Server
def login_to_api(dpms_server, dpms_port, dpms_id, client_id, username, password):

    try:
        conn = http.client.HTTPSConnection(dpms_server, port=dpms_port, context=context)
        headers = {"Content-Type": "application/json"}
        payload = {
            "userName": username,
            "password": password
        }
        payload_json = json.dumps(payload)

        endpoint = f"/openapi/authorize/login?dpms_id={dpms_id}&client_id={client_id}"
        conn.request("POST", endpoint, body=payload_json, headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())

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
    finally:
        conn.close()

# Get Authorization Code
def get_code(dpms_server, dpms_port, client_id, dpms_id, csrf_token, session_id):
    #print (csrf_token,client_id,dpms_id)
    try:
        conn = http.client.HTTPSConnection(dpms_server, port=dpms_port, context=context)
        headers = {
        'Csrf-Token': csrf_token,
        'Cookie': f'JSESSIONID={session_id}',
        'Content-Type': 'application/json'
        }

        conn.request("POST", f"/openapi/authorize/code?response_type=code&client_id={client_id}&dpms_id={dpms_id}", body="", headers=headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        #print(data)
        if response.status == 200:
          if data['errorCode'] == 0:
              code = data['result']['code']
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
def get_access_token(dpms_server, dpms_port, code, client_id, client_secret):
    try:
        conn = http.client.HTTPSConnection(dpms_server, port=dpms_port, context=context)
        headers = {"Content-Type": "application/json"}
        payload = {
            "clientId": client_id,
            "clientSecret": client_secret
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


def get_sites(dpms_id, accessToken):
    try:
      conn = http.client.HTTPSConnection(dpms_server, port=dpms_port, context=context)
      headers = { "Access-Token": accessToken, "Content-Type": "application/json" }
      conn.request("GET", f"/openapi/v1/{dpms_id}/sites", body="", headers=headers )
      data = json.loads(conn.getresponse().read())
      siteList = data['result']['content']
      return siteList
    
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close()


def add_site(dpms_id, accessToken, payload):
    try:
      conn = http.client.HTTPSConnection(dpms_server, port=dpms_port, context=context)
      headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
      conn.request("POST", f"/openapi/v1/{dpms_id}/sites", body=json.dumps(payload), headers=headers )
      data = json.loads(conn.getresponse().read())
      #print(data)
    
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close()    

def remove_sites(accessToken, siteId):
    try:
      conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
      headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
      conn.request("DELETE", f"/openapi/v1/{dpms_id}/sites/{siteId}", body="", headers=headers )
      #print(accessToken, siteId)
      data = json.loads(conn.getresponse().read())
      # print(data)
    
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

# Declare Variables
# Extract dpms information from yaml file
dpmsData = yaml2json('dpms.yaml')
dpms_server = dpmsData['dpms']['server']
dpms_port = dpmsData['dpms']['port']
dpms_id = dpmsData['dpms']['dpmsID']
client_id = dpmsData['dpms']['clientID']
client_secret = dpmsData['dpms']['clientSecret']
username = dpmsData['dpms']['userName']
password = dpmsData['dpms']['userPassword']
new_sites = dpmsData['sites']['newSites']
delete_sites = dpmsData['sites']['deleteSites']

def main():
    print(dpms_server, dpms_port, dpms_id)
    (crsfToken, sessionId) = login_to_api(dpms_server, dpms_port, dpms_id, client_id, username, password)
    print('CRSF-Token: ',crsfToken, 'Session ID: ', sessionId)
    code = get_code(dpms_server, dpms_port, client_id, dpms_id, crsfToken, sessionId )
    print('Authorization Code:', code)
    token = get_access_token(dpms_server, dpms_port, code, client_id=client_id, client_secret=client_secret)
    print('Access Token:', token)
    siteList = get_sites(dpms_id=dpms_id, accessToken=token)
    sites = []

    # Create New Sites
    for site in siteList:
        #print(site)
        sites.append(site['siteName'])
       
    print (sites)
    for new_site in new_sites:
      payload = {"siteName": new_site}
      print(f'Adding New Site "{new_site}"')
      add_site(dpms_id, token, payload)
      print(get_sites(dpms_id=dpms_id, accessToken=token))

    # Delete Sites
    #print (delete_sites)
    for delete_site in delete_sites:
      #print (delete_site)
      for site in get_sites(dpms_id=dpms_id, accessToken=token):
          if site['siteName'] == delete_site:
              siteId = site['siteId']
      #print(token, siteId)
      print(f'Removing site "{delete_site}"')
      remove_sites(token, siteId)
    print(get_sites(dpms_id=dpms_id, accessToken=token))


if __name__ == "__main__":
    main()
