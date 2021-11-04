#!/usr/bin/env python3
import os, json
import argparse
from datetime import datetime
from sys import stderr
import requests

BASE_AUTH_URL = 'https://account.splunk.com/api/v1/okta/auth'
DOWNLOAD_URL = 'https://splunkbase.splunk.com/app/{APPID}/release/{APPVER}/download/?origin=asc&lead=true'
SESSION_FILE = '{HOME}/.cache/splunk-session'

def get_cookies(cookies):
    '''Check if given cookies are expired.

    @param {dict} cookies   Undefined or cookies from cached session.
    @returns Undefined if cookies is undefined or expired
    '''
    if not args.auth and cookies:
        exp = cookies.get('expiration')
        if exp and datetime.now() < datetime.strptime(exp, "%a, %d %b %Y %H:%M:%S %Z"):
            return cookies

# Main
parser = argparse.ArgumentParser(description='Program for downloading app from Splunkbase',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
Environment Variables:

    SPLUNK_USER         User id for login to Splunk for download;
    SPLUNK_USERPW       Password for the SPLUNK_USER above.

FILES:

    ${HOME}/.cache/splunk-session     Session data

This script is inspired by https://github.com/tfrederick74656/splunkbase-download
    '''
)
parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
parser.add_argument('-a', '--auth', action='store_true', help='Force an authentication.')
parser.add_argument('-u', '--userid', help='Specify a Splunk account name.')
parser.add_argument('-p', '--userpw', help='Specify password for the Splunk account.')
parser.add_argument('app_id', type=int, help='The numerical Splunk app ID')
parser.add_argument('app_version', type=str, help='The Splunk app version, usually x.y.z')
parser.add_argument('-f', '--filename', help='Specify a local filename')
args = parser.parse_args()
print('Download Splunkbase app {0}, version {1}'.format(args.app_id, args.app_version))

# Read cached login info if any:
session_file = SESSION_FILE.format(**os.environ)
session = {}
try:
    with open(session_file) as f:
        session = json.load(f)
except FileNotFoundError as err:
    pass

# Authenticate user if session data does not exist, or expired:
cookies = get_cookies(session.get('cookies'))
if not cookies:
    '''Authenticate the user

    Authenticate aginst Splunk's website (Okta) and return 'sid' and "SSOID" cookies.
    Also return the 'status_code', 'status', and 'msg' fields from the server's reply.
    '''
    print('Authenticating...')
    resp = requests.post(
        BASE_AUTH_URL,
        json = {
            "username": args.userid or os.environ.get('SPLUNK_USER'),
            "password": args.userpw or os.environ.get('SPLUNK_USERPW')
        },
        headers = {
            "Accept": 'application/json',
            'Content-Type': 'application/json'
        }
    )
    if resp.status_code != 200:
        print(resp.status_code, ':', resp.text)
        exit(2)
    session = resp.json()
    cookies = session.get('cookies')
    try:
        with open(session_file, 'w') as f:
            json.dump(session, f)
    except FileNotFoundError as err:
        print(err, stderr) # Continue to download.

# Downloading app package:
#
# Download an app from Splunkbase give the app ID, app version, and session cookies.
# Acceptable session cookies are 'sid' and 'SSOID', or alternatively 'sessionid'.
url = DOWNLOAD_URL.format(APPID=args.app_id, APPVER=args.app_version)
cookies_new = { 'SSOSID': cookies['ssoid_cookie'], 'sid': cookies['xaraya_cookie'] }
print(cookies_new)
# NOTE the stream=True parameter below
print('Downloading', url)
with requests.get(url, stream=True, cookies=cookies_new) as r:
    r.raise_for_status()
    filename = args.filename or '/dev/null'
    with open(filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=8192): 
            if chunk: f.write(chunk)
    print('File {0} downloaded.'.format(filename))