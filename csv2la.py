import json
import requests
import datetime
import hashlib
import hmac
import base64
import csv
import os

LOG_FILE = 'logfile.log'
# The log type is the name of the event that is being submitted
log_type = os.environ['LOG_TYPE'].rstrip("\n\r")
# Update the customer ID to your Log Analytics workspace ID
customer_id = os.environ['CUSTOMER_ID'].rstrip("\n\r")
# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = os.environ['SHARED_KEY'].rstrip("\n\r")
fieldnames = ("Domain", "ReceiveTime", "SerialNum", "Type", "Subtype", "ConfigVersion", "GenerateTime", "SourceIP", "DestinationIP",
	"NATSourceIP", "NATDestinationIP", "Rule", "SourceUser", "DestinationUser", "Application", "VirtualSystem", "SourceZone", "DestinationZone",
	"InboundInterface", "OutboundInterface", "LogAction", "TimeLogged", "SessionID", "RepeatCount", "SourcePort", "DestinationPort", "NATSourcePort",
	"NATDestinationPort", "Flags", "Protocol", "Action", "URL", "ThreatContentName", "Category", "Severity", "Direction", "Seqno", "ActionFlags",
	"SourceLocation", "DestinationLocation", "Cpadding_th", "ContentType", "Pcap_id", "Filedigest", "Cloud", "Url_idx", "User_agent", "Filetype", "Xff",
	"Referer", "Sender", "Subject", "Recipient", "Reportid")  
json_data = []
#the with statement is better since it handles closing your file properly after usage.
with open(LOG_FILE, 'r') as csvfile:
    #python's standard dict is not guaranteeing any order
    reader = csv.DictReader(csvfile, fieldnames)
    for row in reader:
        entry = {}
        for field in fieldnames:
            entry[field] = row[field]
        json_data.append(entry) 

body = json.dumps(json_data)

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

post_data(customer_id, shared_key, body, log_type)