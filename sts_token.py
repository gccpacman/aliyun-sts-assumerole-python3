import requests
import datetime
import random
from urllib import parse

import hashlib
import hmac
import base64

roleArn = "---role_name---"
accessKeyId = "---access_id---"
accessSecret = "---access_key---"
roleSessionName = "bestsession"
durationSeconds = "1000"
version = "2015-04-01"
signatureMethod = "HMAC-SHA1"
signatureVersion = "1.0"
signatureNonce = str(random.randint(0, 10000))
timeStamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
action = "AssumeRole"

presign_url_list = [
    "AccessKeyId={}".format(parse.quote_plus(accessKeyId)),
    "Action={}".format(parse.quote_plus(action)),
    "RoleArn={}".format(parse.quote_plus(roleArn)),
    "DurationSeconds={}".format(parse.quote_plus(durationSeconds)),
    "RoleSessionName={}".format(parse.quote_plus(roleSessionName)),
    "Version={}".format(parse.quote_plus(version)),
    "SignatureMethod={}".format(parse.quote_plus(signatureMethod)),
    "SignatureVersion={}".format(parse.quote_plus(signatureVersion)),
    "SignatureNonce={}".format(parse.quote_plus(signatureNonce)),
    "Timestamp={}".format(parse.quote_plus(timeStamp)),
    "Format={}".format('JSON')
]
presign_url = '&'.join(sorted(presign_url_list))
encode_message = "GET&" + parse.quote_plus("/") + "&" + parse.quote_plus(presign_url)
print("\nEncode Message:" +  encode_message)

hmac_key = accessSecret + "&"
hmac_code = hmac.new(hmac_key.encode(), encode_message.encode(), hashlib.sha1).digest()
signature = base64.b64encode(hmac_code).decode().strip()
print("\nSigature:" + signature)

request_url = "https://sts.aliyuncs.com/?"+ presign_url + '&Signature={}'.format(parse.quote_plus(signature))
print("\nRequest Url:" +  request_url)

rsp = requests.get(request_url)

print("\nResponse Text:" +  rsp.text)
