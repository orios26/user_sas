import base64
import requests
from urllib.parse import unquote
from collections import OrderedDict
import hmac
import hashlib
import datetime
from requests.api import request


request_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


def createCanonicalizedHeaders(azure_request_headers):
    """Canonicalized Headers: Following steps must be applied
    1. Get all headers starting with x-ms
    2. Ensure all headers are presented in lowercase and a particular header value shows up only once
    3. Lexicographically sort the headers
    4. Replace any linear whitespace in header value with single space
    """
    request_headers = azure_request_headers
    x_ms_headers = {key: value for key,
                    value in request_headers.items() if "x-ms" in key}

    dedup_x_ms_headers = {}
    for key, value in x_ms_headers.items():
        if key not in dedup_x_ms_headers.keys():
            dedup_x_ms_headers[key.lower()] = value

    lex_sort_headers = OrderedDict(
        sorted(dedup_x_ms_headers.items(), key=lambda k: k[0]))

    whitespace_treat_headers = OrderedDict()

    for key, value in lex_sort_headers.items():
        # replace this with regex at some point????
        temp_key = key.replace("\r", " ").replace(
            "\n", " ").replace("\r\n", " ").replace("\t", " ")
        whitespace_treat_headers[temp_key] = value

    canonicalizedHeaderString = ""
    for key, value in whitespace_treat_headers.items():
        canonicalizedHeaderString += f"{key}:{value}\n"
    return canonicalizedHeaderString


def createCanonicalizedResource(azure_request_url):
    remove_https = azure_request_url.replace("https://", "")
    account_name = remove_https.split('.')[0]
    resource_path = remove_https.split('.')[-1].split('/')[1:]
    canonicalizedString = f"/{account_name}/{'/'.join(resource_path)}"
    canonicalizedResource = unquote(canonicalizedString)
    return canonicalizedResource


content_encoding = ""
content_language = ""
content_length = ""
content_md5 = ""
content_type = "application/json"
date = ""
if_modified_since = ""
if_match = ""
if_none_match = ""
if_unmodified_since = ""
range = ""


VERB = "GET"
azure_request_headers = {
    "x-ms-date": request_date,
    "x-ms-version": "2015-12-11",
    "Content-Type": content_type,
    "Accept": "application/json"
}
azure_request_url = "https://otiorgdatalake.blob.core.windows.net/raw/123Directory/newdata"
#azure_request = requests.request(VERB, headers=request_headers, url=url)

azure_canonicalized_header_string = createCanonicalizedHeaders(
    azure_request_headers)
azure_canonicalized_resource_string = createCanonicalizedResource(
    azure_request_url)


stringToSign = VERB + "\n" + content_encoding + "\n" + content_language + "\n" + content_length + "\n" + content_md5 + "\n" + content_type + "\n" + date + "\n" + if_modified_since + \
    "\n" + if_match + "\n" + if_none_match + "\n" + if_unmodified_since + "\n" + range + \
    "\n" + azure_canonicalized_header_string + azure_canonicalized_resource_string

delegated_key = ""
bytes_to_hash = bytes(stringToSign, encoding='utf-8')
decoded_key = base64.b64decode(delegated_key)
signature = base64.b64encode(
    hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
auth_header = f"SharedKey otiorgdatalake:{signature.decode('utf-8')}"
azure_request_headers["Authorization"] = auth_header


azure_request = requests.request(
    VERB, headers=azure_request_headers, url=azure_request_url)
print("headers sent:")
print(azure_request.request.method)
print(azure_request.request.headers)
print(azure_request.request.body)


print(azure_request.status_code)
print(azure_request.content)
print(stringToSign)
