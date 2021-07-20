#!/usr/bin/python3


import http.client
import json
from urllib.parse import urlencode, quote_plus
from getpass import getpass
import base64
import ssl
import argparse
import os

# Create the command line argument parser
parser = argparse.ArgumentParser(description="OP5 API Query to CSV")

# Add the groups for the required and optional command line arguments. Also hide the default grouping
parser._action_groups.pop()
required = parser.add_argument_group('Required Arguments')
optional = parser.add_argument_group('Modifier Arguments')

# Add the command line arguments that are required.
required.add_argument("-u", "--username", help="OP5 API username", type=str, required=True)
required.add_argument("-f", "--file", help="Path to file with hosts to update", type=str, required=True)
required.add_argument("-j", "--jsonfile", help="Path to file with json of variable", type=str, required=True)
# Add the command line arguments that are optional.
optional.add_argument("-s", "--server", help="OP5 Server DNS Name or IP. Defaults to localhost", default="localhost", type=str)
optional.add_argument("-i", "--insecure", help="Allow invalid and self signed SSL Certificates. This argument has no options", action='store_true')

# Parse the arguments into variables.
args = parser.parse_args()

# Determine if we are going to connect accepting any SSL certificate or require validation.
if args.insecure:
    conn = http.client.HTTPSConnection(
        args.server,
        context=ssl._create_unverified_context()
    )
else:
    conn = http.client.HTTPSConnection(
        args.server
    )

# Get the password input from user
apipw=getpass("OP5 API Password:")


with open(args.jsonfile) as varsjson:
    payload=json.load(varsjson)
    

# Create the headers to allow authentication and return encoding.
headers = {
    'accept': "application/json",
    'Authorization': 'Basic {auth_string}'.format(auth_string=base64.b64encode(str.encode('{username}:{password}'.format(username=args.username, password=apipw))).decode('utf=8'))
}

with open(args.file) as hostsfile:
    host2up=hostsfile.read().splitlines()
for host in range(len(host2up)):
    conn.request("PATCH", "/api/config/host/{host2update}?format=json".format(host2update=host2up[host]), urlencode(payload, quote_via=quote_plus), headers)
    res = conn.getresponse()
    data = res.read()

conn.request("POST", "/api/config/change?format=json",'',headers)