import base64
import hashlib
import hmac
import time
import uuid
from urllib.parse import urlparse
import json

# key is the private key to enter
key = ""

timestamp = str(time.time())
nonce = str(uuid.uuid4())

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True


def generate_signature(url="", content=""):
    path = urlparse(url).path

    request_content_base64string = ""
    if content != "":
        if is_json(content):
            json_loaded = json.loads(json.dumps(content)).replace(" ", "").encode('utf-8')
            request_content_base64string = base64.b64encode(hashlib.md5(json_loaded).digest())
            request_content_base64string = request_content_base64string.decode("utf-8")+"\n"

    signatureRaw = request_content_base64string + timestamp + "\n" + nonce + "\n" + path
    signature = hmac.new(bytes(key, 'UTF-8'), signatureRaw.encode(), hashlib.sha256).hexdigest()

    return signature


# Example of URL = "https://use1-tauc-openapi.tplinkcloud.com/v1/openapi/service-activation-services/network"
# Example of BODY = '{ "networkName": "22385J0C00128", "username": "Ori_123", "meshUnitList": [ { "sn": "22385J0C00128", "mac": "5CE93184FC30" } ] }'
#URL = ""
#BODY = ''
#generate_signature(URL, BODY)
