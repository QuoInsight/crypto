from Crypto.Cipher import DES3
def decryptDES3(p_data, p_key):
  cipher = DES3.new(bytes(p_key[:24], encoding='ascii'), DES3.MODE_CBC, '\0'*8)
  decryptData = cipher.decrypt( bytes.fromhex(p_data) )
  decryptData = str(decryptData, encoding='ascii', errors='ignore')
  return decryptData
#
