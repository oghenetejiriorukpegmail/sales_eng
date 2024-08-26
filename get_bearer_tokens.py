import http.client
import ssl
import json

def get_bearer_tokens():
  # Define the paths to your certificate and key files
  cert_file_path = 'certs/client.crt'
  key_file_path = 'certs/client.key'

  # Create an SSL context
  context = ssl.create_default_context()

  # Load the client certificate and key
  context.load_cert_chain(cert_file_path, key_file_path)  # Using positional arguments

  # Create an HTTPS connection with the SSL context
  conn = http.client.HTTPSConnection("use1-tauc-openapi.tplinkcloud.com", context=context)

  # Payload and headers remain the same
  payload = 'client_id=8af886fd8a6e6d48018a855401110320&client_secret=6b42162e88a24e2bb0496ba7ccac72e3&grant_type=client_credentials'
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  # Make the request
  conn.request("POST", "/v1/openapi/token", payload, headers)

  # Get the response
  res = conn.getresponse()
  data = res.read()
  data_dict = json.loads(data.decode("utf-8"))


  # Print the response
  print(data.decode("utf-8"))

  bearer_token = data_dict["result"]["access_token"]
  
  print(bearer_token)
  with open('bearer_token', 'w') as write_token:
    write_token.write(bearer_token)

  return bearer_token

get_bearer_tokens()