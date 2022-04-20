import hmac
import hashlib
import base64
from urllib.parse import unquote

from collections import OrderedDict


URL = "https://otiorgdatalake.blob.core.windows.net/raw/123Directory/newdata"
split = URL.replace("https://", "").split("/")
account_name = split[0].split(".")[0]
canonicalizedResourceOriginal = f"/blob/{account_name}/{'/'.join(split[1:-1])}"
canonicalDecode = unquote(canonicalizedResourceOriginal)
print(canonicalDecode)


signedPermissions = "r"
signedStart = "2022-04-20T19:41:21Z"
signedExpiry = "2022-04-21T19:41:21Z"
canonicalizedResource = canonicalDecode
signedKeyObjectId = ""
signedKeyTenantId = ""
signedKeyStart = "2022-04-19T01:03:12Z"
signedKeyExpiry = "2022-04-24T01:03:12Z"
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


delegated_key = ""
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
full_token = token_starter + "sig=" + signature.decode('utf-8')
print(full_token)
