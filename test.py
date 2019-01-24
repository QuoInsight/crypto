
# [ https://stackoverflow.com/questions/6747042/python-to-c-sharp-aes-cbc-pkcs7 ]
# [ https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/ ]
# [ https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256 ]

#  .\Python34\Lib\site-packages\pkcs7\__init__.py
#  Line#06:__version__ = "0.1.2"
#  Line#45:        lastch = text[-1]                            ## = ord(text[-1])
#  Line#50:                if text[textlen - i - 1] != lastch:  ## if ord(text[textlen - i - 1])
#  Line#85:            enctext += lastch.encode() * leftlen     ## += lastch * leftlen
#  Line#87:            lastch = text[-1]                        ## = ord(text[-1])

import base64
import Crypto.Cipher.AES
import pkcs7

cipherMode = Crypto.Cipher.AES.MODE_CBC
privateKey = "01234567890123456789012345678901"
iv         = '\x00' * 16
paddingEnc = pkcs7.PKCS7Encoder()

data = "Test"
print( data )

aes = Crypto.Cipher.AES.new(privateKey, cipherMode, IV=iv)
encrytedData = aes.encrypt(paddingEnc.encode(data.encode('utf-8')))
print( base64.b64encode(encrytedData) )
#exit()

aes = Crypto.Cipher.AES.new(privateKey, cipherMode, IV=iv)
d = aes.decrypt(encrytedData)
data = paddingEnc.decode(d).decode('utf-8')
print( data )
#exit()

