from Crypto.Cipher import DES3 ## pycryptodome | pycrypto
#from Crypto.Util.Padding import unpad
def decryptDES3(p_data, p_key):
  cipher = DES3.new(p_key[:24].encode('ascii'), DES3.MODE_CBC, bytes('\0'*8,encoding='ascii'))
  decryptData = cipher.decrypt(bytes.fromhex(p_data))

  #decryptData = unpad(decryptData,8,'pkcs7') ## https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#Crypto.Util.Padding.unpad
  decryptData = decryptData[:0-int.from_bytes(decryptData[-1:],byteorder='big')]; ## PKCS#5 and PKCS#7 https://en.wikipedia.org/wiki/Padding_(cryptography)
  ##decryptData = decryptData.rstrip(decryptData[-1:]); ## remove any trailing byte same as last byte decryptData[-1:]
  #decryptData = decryptData.rstrip(b'\x00'); ## remove any trailing null bytes

  decryptData = decryptData.decode("ascii", errors='ignore') ## str(decryptData, encoding='ascii', errors='ignore')
  return decryptData
#
