#!/usr/bin/env python

import SocketServer
import json
import requests
import datetime
import hashlib
import hmac
import base64
import os
#import sys

HOST, PORT = "0.0.0.0", int(os.environ["SYSLOG_PORT"])
# The log type is the name of the event that is being submitted
log_type = os.environ['LOG_TYPE'].rstrip("\n\r") # 'SyslogTest'
 # Update the customer ID to your Log Analytics workspace ID
customer_id = os.environ['CUSTOMER_ID'].rstrip("\n\r")
# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = os.environ['SHARED_KEY'].rstrip("\n\r")
fieldnames = ("Type","Subtype","Source","Destination","Port","Application","Action")
# "$type","$subtype","$src","$dst","$dport","$app","$action"
# based on https://gist.github.com/marcelom/4218010 from Marcelo
class SyslogUDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = str(bytes.decode(self.request[0].strip())).split(",")
        socket = self.request[1]
        #print( "%s : " % self.client_address[0], data)
        json_data=dict(zip(fieldnames, data))
        # print( "%s" % json_data["Source"],json_data["Destination"],json_data["Port"])
        body = json.dumps(json_data)
        post_data(customer_id, shared_key, body, log_type)
#####################
######Functions######  
#####################

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print 'Accepted'
    else:
        print "Response code: {}".format(response.status_code)        

if __name__ == "__main__":   
	try:
		server = SocketServer.UDPServer((HOST,PORT), SyslogUDPHandler)
		server.serve_forever(poll_interval=0.5)
	except (IOError, SystemExit):
		raise
	except KeyboardInterrupt:
		print ("Crtl+C Pressed. Shutting down.")