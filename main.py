#!/usr/bin/python


# Desc: Scan a URL & IP for malicious indicators. Block/permit email addresses in Mimecast.

import os
import sys
import base64
import hashlib
import hmac
import argparse
import uuid
import time
import datetime
import requests


def main():

    parser = argparse.ArgumentParser("Scan a URL & IP for malicious indicators. Block/permit addresses in Mimecast.")

    parser.add_argument("-u", "--url", help="Scan a URL for malicious characteristics")
    parser.add_argument("-i", "--ip", help="Scan an IP address for any malicious activities seen within 80 days")
    parser.add_argument("-a", "--action", help="Permit (to bypass spam checks) or block (to reject the email)")
    parser.add_argument("-b", "--blocked-senders", help="Add email to the blocked senders profile group AKA all users ")
    parser.add_argument("-p", "--permitted-senders", help="Add email to the permitted senders profile group AKA all users ")
    parser.add_argument("-m", "--mime", action='store_true', help=" Use to access Managed Senders")
    parser.add_argument("-t", "--to", help="The email address of recipient to permit or block")
    parser.add_argument("-s", "--sender", help="The email address of sender to permit or block")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")  # configure verbose

    args = parser.parse_args()

    def ip_scan(ip):

        def update_progress(job_title, progress):
            length = 20 # modify this to change the length
            block = int(round(length*progress))
            msg = "\r{0}: [{1}] {2}%".format(job_title, "#"*block + "-"*(length-block), round(progress*100, 2))
            if progress >= 1: msg += " DONE\r\n"
            sys.stdout.write(msg)
            sys.stdout.flush()

        for i in range(100):
            time.sleep(0.01)  # speed of loading bar
            update_progress("Checking the reputation for: " + ip, i/100.0)
        update_progress(ip, 1)

        # AbuseIPDB setup
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        query_string = {
            "ipAddress": ip,
            "maxAgeInDays": "80"
        }
        headers = {
            "Key": os.environ.get("ABIPDB_KEY"),
            "verbose": "yes"
        }
        # This sends query to the AbuseIPDB API
        ip_response = requests.get(abuse_url, params=query_string, headers=headers)
        results = ip_response.json()
        if results["data"]["abuseConfidenceScore"] <= 10:
            print("The IP abuse score is less than 10, but this is a conservative number.")
            print("Please see IP metadata below:")
            print("Abuse Score: " + str(results["data"]["abuseConfidenceScore"]))
            print("Country: " + results["data"]["countryCode"])
            print("ISP: " + results["data"]["isp"])
            print("Domain: " + results["data"]["domain"])
        elif results["data"]["abuseConfidenceScore"] >= 10:
            print("The IP abuse score is greater than 10, while 10 is conservative consider blocking the IP")
            print("Please see IP metadata below:")
            print("Abuse Score: " + str(results["data"]["abuseConfidenceScore"]))
            print("Country: " + results["data"]["countryCode"])
            print("ISP: " + results["data"]["isp"])
            print("Domain: " + results["data"]["domain"])
        elif results["data"]["abuseConfidenceScore"] >= 30:
            print("The abuse score is 30 and above, I strongly recommend blocking this. See IP metadata below: ")
            print("Please see IP metadata below:")
            print("Abuse Score: " + str(results["data"]["abuseConfidenceScore"]))
            print("Country: " + results["data"]["countryCode"])
            print("ISP: " + results["data"]["isp"])
            print("Domain: " + results["data"]["domain"])

    def url_scan(url):

        def update_progress(job_title, progress):
            length = 20 # modify this to change the length
            block = int(round(length*progress))
            msg = "\r{0}: [{1}] {2}%".format(job_title, "#"*block + "-"*(length-block), round(progress*100, 2))
            if progress >= 1: msg += " DONE\r\n"
            sys.stdout.write(msg)
            sys.stdout.flush()

        for i in range(100):
            time.sleep(0.01)  # speed of loading bar
            update_progress("Checking the reputation for: " + url, i/100.0)
        update_progress(url, 1)

        # This will scan a URL via VirusTotal if the url flag is used
        vt_api = "https://www.virustotal.com/vtapi/v2/url/report"
        vt_params = {
        "apikey": os.environ.get("VT_KEY"),
        "resource": url,
        "allinfo": "True",
        "scan": "1"
        }
        url_response = requests.post(vt_api, data=vt_params)
        # url_output = (json.loads(url_response.text))
        url_output = url_response.json()
        try:
            if url_output["positives"] > 0:
                print("{}/70 vendors has flagged this site as malicious".format(url_output["positives"]))
            else:
                print("URL has not been flagged by any Antivirus vendors")
        except KeyError:
            print("Error, please check the URL format.")

    def managed_senders(sender, to, action):
        # Setup required variables
        # Setup required variables and set keys as environment variables for security purposes.

        base_url = "https://us-api.mimecast.com"
        uri = "/api/managedsender/permit-or-block-sender"
        url = base_url + uri
        access_key = os.environ.get("MIME_ACCESS_KEY")
        secret_key = os.environ.get("MIME_SECRET_KEY")
        app_id = os.environ.get("MIME_APP_ID")
        app_key = os.environ.get("MIME_APP_KEY")
        delimiter = ":"

        # Generate request header values
        request_id = str(uuid.uuid4())
        hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

        # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        # Below the variables are converted to byte code instead strings

        acc = bytes(access_key, 'UTF-8')
        app = bytes(app_key, 'UTF-8')
        u = bytes(uri, 'UTF-8')
        req = bytes(request_id, 'UTF-8')
        hdr = bytes(hdr_date, 'UTF-8')
        key = bytes(secret_key, 'UTF-8')
        delim = bytes(delimiter, 'UTF-8')

        code = base64.b64decode(key)
        hmac_sha1 = hmac.new(code, delim.join([hdr, req, u, app]), hashlib.sha1).digest()

        # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
        sig = base64.encodebytes(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            'Authorization': b'MC ' + acc + b':' + sig,
            'x-mc-app-id': app_id,
            'x-mc-date': hdr_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }

        payload = {
            'data': [
                {
                    'sender': sender,
                    'to': to,
                    'action': action # permit or block
                }
            ]
        }

        response = requests.post(url=url, headers=headers, data=str(payload))
        res_json = response.json()
        if res_json["meta"]["status"] == 200:
            print("{} managed senders list was successfully modified.".format(to))
        else:
            print("There was an error while processing the request")

    def permitted_senders_group(permitted_senders):

        base_url = "https://us-api.mimecast.com"
        uri = "/api/directory/add-group-member"
        url = base_url + uri
        access_key = os.environ.get("MIME_ACCESS_KEY")
        secret_key = os.environ.get("MIME_SECRET_KEY")
        app_id = os.environ.get("MIME_APP_ID")
        app_key = os.environ.get("MIME_APP_KEY")
        permitted_group = os.environ.get("PERMITTED_SENDERS_ID")
        delimiter = ":"

    # Generate request header values
        request_id = str(uuid.uuid4())
        hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

    # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        acc = bytes(access_key, 'UTF-8')
        app = bytes(app_key, 'UTF-8')
        u = bytes(uri, 'UTF-8')
        req = bytes(request_id, 'UTF-8')
        hdr = bytes(hdr_date, 'UTF-8')
        key = bytes(secret_key, 'UTF-8')
        delim = bytes(delimiter, 'UTF-8')

        code = base64.b64decode(key)
        hmac_sha1 = hmac.new(code, delim.join([hdr, req, u, app]), hashlib.sha1).digest()

    # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
        sig = base64.encodebytes(hmac_sha1).rstrip()

    # Create request headers
        headers = {
            'Authorization': b'MC ' + acc + b':' + sig,
            'x-mc-app-id': app_id,
            'x-mc-date': hdr_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
         }
        payload = {
            'data': [
             {
                'id': permitted_group,
                'emailAddress': permitted_senders,
                # 'domain': 'String'
             }
            ]
          }

        r = requests.post(url=url, headers=headers, data=str(payload))
        r_json = r.json()

        if r_json["meta"]["status"] == 200:
            print("{} has successfully been added to the Permitted profile group".format(permitted_senders))
        else:
            print("Uh oh, something went wrong. Please try via the Mimecast UI")

    def blocked_senders_group(blocked_senders):

        base_url = "https://us-api.mimecast.com"
        uri = "/api/directory/add-group-member"
        url = base_url + uri
        access_key = os.environ.get("MIME_ACCESS_KEY")
        secret_key = os.environ.get("MIME_SECRET_KEY")
        app_id = os.environ.get("MIME_APP_ID")
        app_key = os.environ.get("MIME_APP_KEY")
        blocked_group = os.environ.get("BLOCKED_SENDERS_ID")
        delimiter = ":"

        # Generate request header values
        request_id = str(uuid.uuid4())
        hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"

        # Create the HMAC SHA1 of the Base64 decoded secret key for the Authorization header
        acc = bytes(access_key, 'UTF-8')
        app = bytes(app_key, 'UTF-8')
        u = bytes(uri, 'UTF-8')
        req = bytes(request_id, 'UTF-8')
        hdr = bytes(hdr_date, 'UTF-8')
        key = bytes(secret_key, 'UTF-8')
        delim = bytes(delimiter, 'UTF-8')

        code = base64.b64decode(key)
        hmac_sha1 = hmac.new(code, delim.join([hdr, req, u, app]), hashlib.sha1).digest()

        # Use the HMAC SHA1 value to sign the hdrDate + ":" requestId + ":" + URI + ":" + appkey
        sig = base64.encodebytes(hmac_sha1).rstrip()

        # Create request headers
        headers = {
            'Authorization': b'MC ' + acc + b':' + sig,
            'x-mc-app-id': app_id,
            'x-mc-date': hdr_date,
            'x-mc-req-id': request_id,
            'Content-Type': 'application/json'
        }
        payload = {
            'data': [
                {
                    'id': blocked_group,
                    'emailAddress': blocked_senders,
                    # 'domain': 'String'
                }
            ]
        }

        r = requests.post(url=url, headers=headers, data=str(payload))
        r_json = r.json()

        if r_json["meta"]["status"] == 200:
            print("{} has successfully been added to the Blocked profile group".format(blocked_senders))
        else:
            print("Uh oh, something went wrong. Please try via the Mimecast UI")

    if args.ip:
        ip_scan(args.ip)
    elif args.url:
        url_scan(args.url)
    elif args.mime:
        managed_senders(args.sender, args.to, args.action)
    elif args.permitted_senders:
        permitted_senders_group(args.permitted_senders)
    elif args.blocked_senders:
        blocked_senders_group(args.blocked_senders)

    
if __name__ == '__main__':
    main()
