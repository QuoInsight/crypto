from Crypto.Cipher import DES3 ## pycryptodome | pycrypto
from Crypto.Util.Padding import unpad
def decryptDES3(p_data, p_key):
  cipher = DES3.new(p_key[:24].encode('ascii'), DES3.MODE_CBC, bytes('\0'*8,encoding='ascii'))
  decryptData = cipher.decrypt(bytes.fromhex(p_data))
  decryptData = unpad(decryptData,8) ## PaddingMode.PKCS7
  decryptData = decryptData.decode("ascii", errors='ignore') ## str(decryptData, encoding='ascii', errors='ignore')
  return decryptData
#
