
# [ https://stackoverflow.com/questions/6747042/python-to-c-sharp-aes-cbc-pkcs7 ]
# [ https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/ ]
# [ https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256 ]

#  .\Python34\Lib\site-packages\pkcs7\__init__.py
#  Line#06:__version__ = "0.1.2"
#  Line#45:        lastch = text[-1]                            ## = ord(text[-1])
#  Line#50:                if text[textlen - i - 1] != lastch:  ## if ord(text[textlen - i - 1])
#  Line#85:            enctext += lastch.encode() * leftlen     ## += lastch * leftlen
#  Line#87:            lastch = text[-1]                        ## = ord(text[-1])

import Crypto.Cipher.AES
import pkcs7

cipherMode = Crypto.Cipher.AES.MODE_CBC
privateKey = "01234567890123456789012345678901"
iv         = '\x00' * 16
paddingEnc = pkcs7.PKCS7Encoder()

filePath = r"B:\data.txt"
with open(filePath+".encrypted", 'wb') as f1:
  with open(filePath, 'rb') as f0:
    aes = Crypto.Cipher.AES.new(privateKey, cipherMode, IV=iv) ##!! must reinitialize this for each file !!##
    while True:
      data = f0.read(1024)
      if len(data) == 0: break
      encyptedData = aes.encrypt(paddingEnc.encode(data))
      f1.write(bytearray(encyptedData))
      #print("encyptedData: " + str(base64.b64encode(encrytedData).decode())); break
    #
  #
#
#exit()

filePath = r"B:\data.txt.encrypted"
with open(filePath+".out", 'wb') as f1:
  with open(filePath, 'rb') as f0:
    aes = Crypto.Cipher.AES.new(privateKey, cipherMode, IV=iv) ##!! must reinitialize this for each file !!##
    while True:
      data = f0.read(1024)
      if len(data) == 0: break
      decyptedData = paddingEnc.decode(aes.decrypt(data))
      f1.write(decyptedData)
    #
  #
#
#exit()
