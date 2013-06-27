import binascii
import hmac
import hashlib

PAYLOAD = binascii.unhexlify('9000c832686a0000e03c04030402')
AUTH_KEY = binascii.unhexlify('0000000000000000000000000000000000012345')

print type(PAYLOAD)
print type(AUTH_KEY)
print ""

HASH = (hmac.new(AUTH_KEY,PAYLOAD,hashlib.sha1)).hexdigest()[:20]

#PAY_HASH = HASH.hexdigest()[:20]

print binascii.b2a_hex(PAYLOAD)
print binascii.b2a_hex(AUTH_KEY)
print HASH

PACKET = binascii.b2a_hex(PAYLOAD) + HASH

print PACKET


# 27 86 3f 89 d5 a7 15 a8 31 55