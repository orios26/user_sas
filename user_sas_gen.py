import hmac
import hashlib
import base64
from urllib.parse import unquote

from collections import OrderedDict


def createCanonicalizedResource(resource_URI):
    remove_https = resource_URI.replace("https://", "")
    account_name = remove_https.split('.')[0]
    resource_path = remove_https.split('.')[-1].split('/')[1:]
    canonicalizedString = f"/blob/{account_name}/{'/'.join(resource_path)}"
    canonicalizedResource = unquote(canonicalizedString)
    return canonicalizedResource


URL = ""
# RESOURCE URI OF FOLDER/BLOB/CONTAINER TO GIVE ACCESS TO
# EXAMPLE: https://storageaccountname.blob.core.windows.net/raw/123Directory/newdata
canonicalDecode = createCanonicalizedResource(URL)
print(canonicalDecode)


signedPermissions = "rw"
signedStart = "2022-05-31T01:03:12Z"
signedExpiry = "2022-06-01T01:03:12Z"
canonicalizedResource = canonicalDecode
signedKeyObjectId = ""  # SignedOid returned from get user delegation key call
signedKeyTenantId = ""  # SignedTid returned from get user delegation key call
signedKeyStart = "2022-05-31T01:03:12Z"
signedKeyExpiry = "2022-06-01T01:03:12Z"
signedKeyService = "b"
signedKeyVersion = "2020-02-10"
signedAuthorizedUserObjectId = ""
signedUnauthorizedUserObjectId = ""
signedCorrelationId = ""
signedIP = ""
signedProtocol = "https"
signedVersion = "2020-02-10"
signedResource = "b"
signedSnapshotTime = ""
signedEncryptionScope = ""
rscc = ""
rsdd = ""
rscl = ""
rsct = ""


delegated_key = ""  # user delegation key returned from api call
stringToSign = signedPermissions + "\n" + signedStart + "\n" + signedExpiry + "\n" + canonicalizedResource + "\n" + signedKeyObjectId + "\n" + signedKeyTenantId + "\n" + signedKeyStart + "\n" + signedKeyExpiry + "\n" + signedKeyService + "\n" + signedKeyVersion + "\n" + \
    signedAuthorizedUserObjectId + "\n" + signedUnauthorizedUserObjectId + "\n" + signedCorrelationId + "\n" + signedIP + "\n" + signedProtocol + "\n" + \
    signedVersion + "\n" + signedResource + "\n" + signedSnapshotTime + "\n" + \
    signedEncryptionScope + "\n" + rscc + "\n" + rsdd + "\n" + rscl + "\n" + rsct

bytes_to_hash = bytes(stringToSign, encoding='utf-8')
decoded_key = base64.b64decode(delegated_key)
signature = base64.b64encode(
    hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
print(signature)

# define sas config object from the values in string to sign
sas_config = OrderedDict(sp=signedPermissions, st=signedStart, se=signedExpiry, skoid=signedKeyObjectId, sktid=signedKeyTenantId, skt=signedKeyStart, ske=signedKeyExpiry, sks=signedKeyService, skv=signedKeyVersion, saoid=signedAuthorizedUserObjectId, suoid=signedUnauthorizedUserObjectId, scid=signedCorrelationId, sip=signedIP, spr=signedProtocol, sv=signedVersion, sr=signedResource, ses=signedEncryptionScope
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
