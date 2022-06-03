import hmac
import hashlib
import base64
from urllib.parse import unquote

from collections import OrderedDict


def createCanonicalizedResource(resource_URI):
    remove_https = resource_URI.replace("https://", "")
    account_name = remove_https.split('.')[0]
    substring_template = remove_https.replace(".core.windows.net", "#")
    resource_path = ''.join(substring_template.split("#")[1:])
    canonicalizedString = f"/blob/{account_name}{resource_path}"
    canonicalizedResource = unquote(canonicalizedString)
    return canonicalizedResource


# RESOURCE URI OF FOLDER/BLOB/CONTAINER TO GIVE ACCESS TO
# EXAMPLE: https://storageaccountname.blob.core.windows.net/raw/123Directory/newdata
URL = "https://fr.txt"
canonicalDecode = createCanonicalizedResource(URL)
print(canonicalDecode)


signedPermissions = "rw"
signedStart = "2022-06-03T08:02:55Z"
signedExpiry = "2022-06-04T09:02:55Z"
canonicalizedResource = canonicalDecode
# SignedOid returned from get user delegation key call
signedKeyObjectId = ""
# SignedTid returned from get user delegation key call
signedKeyTenantId = ""
# SignedStart returned from get user delegation key call
signedKeyStart = "2022-06-03T08:02:55Z"
# SignedExpiry returned from get user delegation key call
signedKeyExpiry = "2022-06-04T09:02:55Z"
# SignedService returned from get user dedlgation key call
signedKeyService = "b"
# SignedVersion returned from get user delegation key call
signedKeyVersion = "2020-02-10"
signedAuthorizedUserObjectId = ""
signedUnauthorizedUserObjectId = ""
signedCorrelationId = ""
signedIP = ""
signedProtocol = "https"
signedVersion = "2020-02-10"
signedResource = "b"
signedSnapshotTime = ""
signedRscc = ""
signedRscd = ""
signedRsce = ""
signedRscl = ""
signedRsct = ""


# user delegation key returned from api call
delegated_key = ""
stringToSign = (
    signedPermissions + "\n"
 + signedStart + "\n" 
 + signedExpiry + "\n" 
 + canonicalizedResource + "\n" 
 + signedKeyObjectId + "\n" 
 + signedKeyTenantId + "\n" 
 + signedKeyStart + "\n" 
 + signedKeyExpiry + "\n" 
 + signedKeyService + "\n" 
 + signedKeyVersion + "\n" 
 + signedAuthorizedUserObjectId + "\n" 
 + signedUnauthorizedUserObjectId + "\n" 
 + signedCorrelationId + "\n" 
 + signedIP + "\n" 
 + signedProtocol + "\n" 
 + signedVersion + "\n" 
 + signedResource + "\n" 
 + signedSnapshotTime + "\n"  
 + signedRscc + "\n" 
 + signedRscd + "\n" 
 + signedRsce + "\n" 
 + signedRscl + "\n" )

print(stringToSign)

bytes_to_hash = bytes(stringToSign, encoding='utf-8')
decoded_key = base64.b64decode(delegated_key)
signature = base64.b64encode(
    hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
print(signature)

# define sas config object from the values in string to sign
sas_config = OrderedDict(sp=signedPermissions, st=signedStart, se=signedExpiry, skoid=signedKeyObjectId, sktid=signedKeyTenantId, skt=signedKeyStart, ske=signedKeyExpiry, sks=signedKeyService, skv=signedKeyVersion, saoid=signedAuthorizedUserObjectId, suoid=signedUnauthorizedUserObjectId, scid=signedCorrelationId, sip=signedIP, spr=signedProtocol, sv=signedVersion, sr=signedResource, rscc = signedRscc, rscd=signedRscd, rsce = signedRsce, rscl = signedRscl, rsct = signedRsct 
                         )


# create a sas token from the sas config, append the signature later
def generate_user_delegation_sas(sas_config):
    present_values = {key: value for key,
                      value in sas_config.items() if value != ""}
    generate_string = ""
    for key, value in present_values.items():
        generate_string += f"{key}={value}&"
    return generate_string


token_starter = generate_user_delegation_sas(sas_config=sas_config)
full_token = token_starter + "sig=" + \
    signature.decode('utf-8').replace("+", "%2B")
print(full_token)