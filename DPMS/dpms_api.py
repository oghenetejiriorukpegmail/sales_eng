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

def configure_vlan(accessToken, vlanBody, vlanID, vlanName):
    #config Service Port
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/l2-feature/vlan/8021q/configs", body="", headers=headers)
        vlanData = json.loads(conn.getresponse().read())
        #print(vlanData, type(vlanData))
        if (vlanName) in str(vlanData):        
            print(f'VLAN ID  "{vlanID}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/l2-feature/vlan/8021q/configs", body=vlanBody, headers=headers)
            resultData = json.loads(conn.getresponse().read())
            #print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'VLAN ID "{vlanID}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring VLAN ID  "{vlanID}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def get_ONU_ID(accessToken):
    conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
    headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
    #print(deviceKey)
    conn.request("GET", f"/openapi/v1/{dpms_id}/onu-devices", body="", headers=headers )
    data = json.loads(conn.getresponse().read())
    print(data)


def config_pon_port(port_no, port_status):
    pass


def get_olts(accessToken):
    conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
    headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
    #print(deviceKey)
    conn.request("GET", f"/openapi/v1/{dpms_id}/olt-devices", body="", headers=headers )
    data = json.loads(conn.getresponse().read())
    print(data)

def get_dba_id(accessToken):
    pass
    
def configure_dba_profile(accessToken, DBABody):
    #config DBA
    try:
      conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
      headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
      #print(deviceKey)
      conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/dba/profiles", body="", headers=headers)
      DBAData = json.loads(conn.getresponse().read())
      #print(DBAData)
      DBAName = dpmsData['PON']['Profile']['DBA']['Profile_Name'] 
      #print (DBAName)
      if DBAName in str(DBAData):
          print(f'DBA profile "{DBAName}" is already present on this OLT')
      else:
        conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/dba/profiles", body=DBABody, headers=headers )
        data = json.loads(conn.getresponse().read())
        if data['result']['errcode'] == 0:
            print(f'DBA Profile "{DBAName}"" Configured Successfully!,', "Data:", data)
        else:
            print(f'Encountered an error configuring DBA Profile "{DBAName}" , Error:', data)
            quit()
     
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def configure_line_profile(accessToken, lineBody):
    #config Line Profile
    try:
      conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
      headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
      #print(deviceKey)
      conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/line-profiles?size=100&number=0", body="", headers=headers)
      lineData = json.loads(conn.getresponse().read())
      #print(lineData)
      lineName = dpmsData['PON']['Profile']['Line']['Profile_Name'] 
      if lineName in str(lineData):
          print(f'Line profile "{lineName}" is already present on this OLT')
      else:
        conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/line-profiles", body=lineBody, headers=headers )
        resultData = json.loads(conn.getresponse().read())
        if resultData['result']['errcode'] == 0:
            print(f'Line Profile "{lineName}" Configured Successfully!,', "Data:", resultData)
        else:
            print(f"Encountered an error configuring Line Profile {lineName}, Error:", resultData)
            quit()

    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def get_line_profile_id(accessToken):
    conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
    headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
    #print(deviceKey)
    conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/line-profiles", body="", headers=headers )
    data = json.loads(conn.getresponse().read())
    #print(data['result']['content'])
    return data['result']['content']

def configure_tcont(accessToken, tcontBody, lineProfileID):
    #config tcont
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/t-conts", body="", headers=headers)
        tcontData = json.loads(conn.getresponse().read())
        #print(tcontData, type(tcontData))
        tcontID = dpmsData['PON']['Profile']['Line']['TCONT']['TCONT_ID']
        tcontList = tcontData['result']['content']
        #print(tcontList)
        if tcontList != []:        
            for tcont in tcontList:
                if  tcont['tcontId'] == tcontID:
                    print(f'TCONT ID  "{tcontID}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/t-conts", body=tcontBody, headers=headers )
            resultData = json.loads(conn.getresponse().read())
            if resultData['result']['errcode'] == 0:
                print(f'TCONT ID "{tcontID}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring TCONT ID  "{tcontID}"", Error:', resultData)
                quit()

    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def configure_gem_ports(accessToken, gemportBody, lineProfileID, gemPortID):
    #config GEM Ports
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/gem-ports", body="", headers=headers)
        gemPortData = json.loads(conn.getresponse().read())
        #print(gemPortData, type(gemPortData))
        
        gemPortList = gemPortData['result']['content']
        #print(gemPortList)
        if gemPortList != []:        
            for gemPort in gemPortList:
                if  gemPort['gemPortId'] == gemPortID:
                    print(f'GEM PORT ID  "{gemPortID}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/gem-ports", body=gemportBody, headers=headers )
            resultData = json.loads(conn.getresponse().read())
            #print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'GEM PORT ID "{gemPortID}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring GEM PORT ID  "{gemPortID}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def configure_gem_port_mapping(accessToken, gemportBody, lineProfileID, gemPortMappingId):
    #config GEM Mapping
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/gem-mappings", body="", headers=headers)
        gemPortMappingData = json.loads(conn.getresponse().read())
        #print(gemPortMappingData, type(gemPortMappingData))
        
        gemPortMappingList = gemPortMappingData['result']['content']
        #print(gemPortMappingList)
        if gemPortMappingList != []:        
            for gemPortMapping in gemPortMappingList:
                if  gemPortMapping['gemPortId'] == gemPortMappingId:
                    print(f'GEM PORT MAPPING  "{gemPortMappingId}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/profile/line/{lineProfileID}/gem-mappings", body=gemportBody, headers=headers )
            resultData = json.loads(conn.getresponse().read())
            #print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'GEM PORT MAPPING "{gemPortMappingId}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring GEM PORT MAPPING  "{gemPortMappingId}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def configure_service_template(accessToken, servicesTemplateBody, servicesName):
    #config Services
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/service-profiles", body="", headers=headers)
        servicesTemplateData = json.loads(conn.getresponse().read())
        #print(servicesTemplateData, type(servicesTemplateData))
        #print(serviceTemplateList)
        if servicesName in str(servicesTemplateData):        
            print(f'SERVICE TEMPLATE  "{servicesName}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/service-profiles", body=servicesTemplateBody, headers=headers )
            resultData = json.loads(conn.getresponse().read())
            #print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'SERVICE TEMPLATE "{servicesName}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring SERVICE TEMPLATE  "{servicesName}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def get_traffic_profile(accessToken, trafficProfileName):
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/traffic-profiles", body="", headers=headers)
        trafficProfileData = json.loads(conn.getresponse().read())
        #print(trafficProfileData['result']['content'], type(trafficProfileData))
        trafficProfileList = trafficProfileData['result']['content']
        for trafficProfile in trafficProfileList:
            if trafficProfileName.lower() == trafficProfile['name'].lower():
                #print(trafficProfile)
                return trafficProfile
      
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def get_traffic_profile_id(accessToken,trafficProfileName):
    trafficprofileData = get_traffic_profile(accessToken, trafficProfileName)
    return trafficprofileData['trafficId']

def configure_traffic_profile(accessToken, trafficProfileBody, trafficProfileName):
    #config Traffic Profile
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/traffic-profiles", body="", headers=headers)
        TrafficProfileData = json.loads(conn.getresponse().read())
        #print(TrafficProfileData, type(TrafficProfileData))
        if trafficProfileName in str(TrafficProfileData):        
            print(f'TRAFFIC PROFILE  "{trafficProfileName}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/traffic-profiles", body=trafficProfileBody, headers=headers)
            resultData = json.loads(conn.getresponse().read())
            #print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'TRAFFIC PROFILE  "{trafficProfileName}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring TRAFFIC PROFILE   "{trafficProfileName}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 

def configure_service_port(accessToken, servicePortBody, servicePortIndex, servicePortDescription):
    #config Service Port
    try:
        conn = http.client.HTTPSConnection(dpms_server, dpms_port, context=context)
        headers = { "Access-Token": accessToken , "Content-Type": "application/json"}
        conn.request("GET", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/service-ports", body="", headers=headers)
        servicePortData = json.loads(conn.getresponse().read())
        #print(servicePortData, type(servicePortData))
        if (servicePortDescription) in str(servicePortData):        
            print(f'SERVICE PORT INDEX  "{servicePortIndex}" is already present on this OLT')
        else:
            conn.request("POST", f"/openapi/v1/{dpms_id}/devices/{deviceKey}/pon/service-ports", body=servicePortBody, headers=headers)
            resultData = json.loads(conn.getresponse().read())
            print(resultData)
            if resultData['result']['errcode'] == 0:
                print(f'SERVICE PORT INDEX "{servicePortIndex}" Configured Successfully!,', "Data:", resultData)
            else:
                print(f'Encountered an error configuring SERVICE PORT INDEX  "{servicePortIndex}"", Error:', resultData)
                quit()
        
    except Exception as e:
      print(f"Error making API request: {e}")
      return None
    finally:
        conn.close() 



# Declare Variables
# Extract dpms information from yaml file
dpmsData = yaml2json('DPMS/dpms.yaml')
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
    accessToken = get_access_token(dpms_server, dpms_port, code, client_id=client_id, client_secret=client_secret)
    print('Access Token:', accessToken)
    siteList = get_sites(dpms_id=dpms_id, accessToken=accessToken)
    sites = []

    '''
    # Create New Sites
    for site in siteList:
        #print(site)
        sites.append(site['siteName'])
       
    print (sites)
    for new_site in new_sites:
      payload = {"siteName": new_site}
      print(f'Adding New Site "{new_site}"')
      add_site(dpms_id, accessToken, payload)
      print(get_sites(dpms_id=dpms_id, accessToken=accessToken))

    # Delete Sites
    #print (delete_sites)
    for delete_site in delete_sites:
      #print (delete_site)
      for site in get_sites(dpms_id=dpms_id, accessToken=accessToken):
          if site['siteName'] == delete_site:
              siteId = site['siteId']
      #print(token, siteId)
      print(f'Removing site "{delete_site}"')
      remove_sites(accessToken, siteId)
    print(get_sites(dpms_id=dpms_id, accessToken=accessToken))
    '''
    #Configure VLAN(S)
    vlanList = dpmsData['L2_Features']['VLAN']['802_1Q_VLAN']
    #print(vlanList)

    for vlan in vlanList:
        vlanID = vlan['VLAN_ID']
        vlanName = vlan['VLAN_Name']
        vlanUntaggedPorts = vlan['Untagged_Ports']
        vlantaggedPorts = vlan['Tagged_Ports']


        vlanBody = {
                    "vlanId": vlanID,
                    "vlanName": vlanName,
                    "unTaggedPorts": vlanUntaggedPorts.upper(),
                    "taggedPorts": vlantaggedPorts.upper()
                    }
        #print(vlanBody)

        configure_vlan(accessToken, json.dumps(vlanBody), vlanID, vlanName)


    #Configure DBA
    DBABody = { "dbaId": dpmsData['PON']['Profile']['DBA']['Profile_ID'],
            "name": dpmsData['PON']['Profile']['DBA']['Profile_Name'],
            "type": dpmsData['PON']['Profile']['DBA']['Type'],
            "fix": dpmsData['PON']['Profile']['DBA']['Fix_Bandwidth'],
            "assure": 0,
            "max": 0
             }
    
    #body = { "dbaId": dpmsData['PON']['Profile']['DBA']['Profile_ID'],"name": dpmsData['PON']['Profile']['DBA']['Profile_Name'],"type": dpmsData['PON']['Profile']['DBA']['Type'],"fix": dpmsData['PON']['Profile']['DBA']['Fix_Bandwidth'],"assure": 0,"max": 0}
    #get_olts(accessToken)
    #uprint(DBABody)
    configure_dba_profile(accessToken, json.dumps(DBABody))

    #Configure Line
    lineBody = { "lineProfileId": dpmsData['PON']['Profile']['Line']['Profile_ID'],
            "name": dpmsData['PON']['Profile']['Line']['Profile_Name'],
            "upstreamFEC": dpmsData['PON']['Profile']['Line']['Upstream_FEC'],
            "mappingMode": dpmsData['PON']['Profile']['Line']['Mapping_Mode'],
            "omccEncrypt": dpmsData['PON']['Profile']['Line']['Encrypt'],
             }
    
    #print(lineBody)
    configure_line_profile(accessToken, json.dumps(lineBody))

    #Configure TCONT
    #Find the Line Profile ID if not given
    get_line_profile_id(accessToken)
    lineProfileID = dpmsData['PON']['Profile']['Line']['Profile_ID']
    lineProfileName = dpmsData['PON']['Profile']['Line']['Profile_Name']
    if  lineProfileID == None:
       lineProfileList = get_line_profile_id(accessToken)
       #(lineProfileList, type(lineProfileList))
       for lineProfile in lineProfileList:
          #print(lineProfile)
          if lineProfileName in str(lineProfile):
             #print(lineProfile)
             lineProfileID = lineProfile['lineProfileId']
             #print(lineProfileID)

    DBANum =  dpmsData['PON']['Profile']['Line']['TCONT']['DBA_Profile_ID']
    tcontID = dpmsData['PON']['Profile']['Line']['TCONT']['TCONT_ID']

    tcontBody = {
        "tcontId": tcontID,
        "dbaId": DBANum
             }
    
    #print(tcontBody)
    configure_tcont(accessToken, json.dumps(tcontBody), lineProfileID)

    #print(dpmsData)
    gemPortList = dpmsData['PON']['Profile']['Line']['GEM_Ports']

    for gemPort in gemPortList:
        gemPortID = gemPort['GEM_Port_ID']
        gemPortTCONTID = gemPort['TCONT_ID']
        gemPortEncrytption = gemPort['Encryption']

        gemPortBody = {
            "gemPortId": gemPortID,
            "tcontId": gemPortTCONTID,
            "encrypt": gemPortEncrytption
            }
        
        #print(gemPortBody)
        configure_gem_ports(accessToken, json.dumps(gemPortBody), lineProfileID, gemPortID)

    gemPortMappingList = dpmsData['PON']['Profile']['Line']['GEM_Mapping_Rules']
    #print(gemPortMappingList)
    
    for gemPortMapping in gemPortMappingList:
        gemPortMappingId = gemPortMapping['GEM_Mapping_ID']
        gemPortId = gemPortMapping['GEM_Port_ID']
        gemPortvlanType = (gemPortMapping['VLAN']['Type']).upper()
        gemPortvlanId = gemPortMapping['VLAN']['ID']


        gemPortMappingBody = {
            "gemMappingId": gemPortMappingId, 
            "gemPortId": gemPortId,
            "vlanType": gemPortvlanType,
            "vlanId": gemPortvlanId
            }
        configure_gem_port_mapping(accessToken, json.dumps(gemPortMappingBody), lineProfileID, gemPortMappingId)

    servicesList = dpmsData['PON']['Profile']['Services']
    #print(servicesList)

    for services in servicesList:
        servicesId = services['Profile_ID']
        servicesName = services['Profile_Name']
        servicesETHNumber = services['ETH_Number']
        servicesETHMaxAdaptiveNumber = services['ETH_Max_Adaptive_Number']
        servicesPOTSNumber = services['POTS_Number']
        servicesPOTSMaxAdaptiveNumber = services['POTS_Max_Adaptive_Number']
        servicesMACLearning = (services['MAC_Learning']).upper()
        servicesNativeVLAN = (services['Native_VLAN']).upper()
        servicesMulticastMode = services['Multicast_Mode']
        servicesMulticastForward = services['Multicast_Forward']


        servicesTemplateBody = {
            "serviceId": servicesId,
            "name": servicesName,
            "ethNum": servicesETHNumber,
            "maxAdaptiveEthNum": servicesETHMaxAdaptiveNumber,
            "potsNum": servicesPOTSNumber,
            "maxAdaptivePotsNum": servicesPOTSMaxAdaptiveNumber,
            "macLearning": servicesMACLearning.upper(),
            "nativeVlan": servicesNativeVLAN.upper(),
            "multicastMode": servicesMulticastMode.upper(),
            "multicastForward": servicesMulticastForward.upper(),
            }
        #print(servicesTemplateBody)
        configure_service_template(accessToken, json.dumps(servicesTemplateBody), servicesName)

    trafficProfileList = dpmsData['PON']['Profile']['Traffic']
    #print(trafficProfileList)
    for trafficProfile in trafficProfileList:
        trafficProfileID = trafficProfile['Profile_ID']
        trafficProfileName = trafficProfile['Profile_Name']
        trafficProfileRateLimitStatus = trafficProfile['Rate_Limit']
        trafficProfileCIR = trafficProfile['CIR']
        trafficProfileCBS = trafficProfile['CBS']
        trafficProfilePIR = trafficProfile['PIR']
        trafficProfilePBS = trafficProfile['PBS']
        trafficProfilePriorityType = trafficProfile['Priority']['Type']
        trafficProfilePriorityValue = trafficProfile['Priority']['Value']
        trafficProfileInnerPriorityType = trafficProfile['Inner_Priority']['Type']
        trafficProfileInnerPriorityValue = trafficProfile['Inner_Priority']['Value']
        trafficProfilePriorityPolicy = trafficProfile['Priority-Policy']


        trafficProfileBody = {
            "name": trafficProfileName,
            "rateLimitStatus": trafficProfileRateLimitStatus.upper(),
            "cirValue": trafficProfileCIR,
            "cbsValue": trafficProfileCBS,
            "pirValue": trafficProfilePIR,
            "pbsValue": trafficProfilePBS,
            "priority": trafficProfilePriorityType.upper(),
            "priorityValue": trafficProfilePriorityValue,
            "innerPriority": trafficProfileInnerPriorityType.upper(),
            "innerPriorityValue": trafficProfileInnerPriorityValue,
            "priorityPolicy": trafficProfilePriorityPolicy.upper(),
            "trafficId": trafficProfileID
            }
        #print(trafficProfileBody)
        configure_traffic_profile(accessToken, json.dumps(trafficProfileBody), trafficProfileName)

    #Configure Service Ports
    servicePortList = dpmsData['PON']['Service_Ports']
    #print(servicePortList)

    for servicePort in servicePortList:
        servicePortIndex = servicePort['index']
        servicePortPonPortId = servicePort['PON_Port']
        servicePortDescription = servicePort['Description']
        servicePortSVLAN = servicePort['SVLAN']
        servicePortGemPortId = servicePort['GEM_ID']
        servicePortUserVlan = servicePort['UserVLAN']['Value']
        servicePortUserVlanPriority = servicePort['UserVLAN']['User_VLAN_Priority']
        servicePorttagAction = servicePort['UserVLAN']['TAG_Action'].upper()
        servicePortONUId = servicePort['ONU_ID']
        servicePortAdminStatus = servicePort['AdminStatus'].upper()
        servicePortstatisticPerformance = servicePort['Performance_Statistics'].upper()
        servicePortEthertype = servicePort['Ethertype'].upper()
        servicePortInboundTrafficProfile = get_traffic_profile_id(accessToken, servicePort['Inbound_Traffic_Profile'].upper())
        servicePortOutboundTrafficProfile = get_traffic_profile_id(accessToken, servicePort['Outbound_Traffic_Profile'].upper())


        servicePortBody = {
            "ponPortId": servicePortPonPortId,
            "ponPortStr": "",
            "svlan": servicePortSVLAN,
            "gemPortId": servicePortGemPortId,
            "userVlan": servicePortUserVlan,
            "userVlanPriority": servicePortUserVlanPriority,
            "tagAction": servicePorttagAction,
            "innerVlan": 0,
            "innerVlanPriority": -1,
            "etherType": servicePortEthertype,
            "inboundTrafficProfileId": servicePortInboundTrafficProfile,
            "outboundTrafficProfileId": servicePortOutboundTrafficProfile,
            "index": servicePortIndex,
            "batchConfig": True,
            "description": servicePortDescription,
            "onuId": servicePortONUId,
            "adminStatus": servicePortAdminStatus,
            "statisticPerformance": servicePortstatisticPerformance
            }
        #print(servicePortBody)
        configure_service_port(accessToken, json.dumps(servicePortBody), servicePortIndex, servicePortDescription)
    
        get_ONU_ID(accessToken)
        get_olts(accessToken)

if __name__ == "__main__":
    for olt in dpmsData['OLTs']:
       deviceKey =  olt   
       main()