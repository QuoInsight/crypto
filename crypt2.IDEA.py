#! /usr/bin/python
# https://stackoverflow.com/a/59122624
# Ported to Python 3.x by CKL036

import struct
 
# --- IDEA block cipher.
 
def _idea_mul(a, b):
  if a:
    if b:
      p = a * b
      b, a = p & 0xffff, p >> 16
      return (b - a + (b < a)) & 0xffff
    else:
      return (1 - a) & 0xffff
    #
  else:
    return (1 - b) & 0xffff
  #
#
 
def _idea_inv(x):
  if x <= 1: return x
  t1, y = divmod(0x10001, x)
  t0 = 1
  while y != 1:  # Eucledian GCD.
    q, x = divmod(x, y)
    t0 += q * t1
    if x == 1: return t0
    q, y = divmod(y, x)
    t1 += q * t0
  #
  return (1 - t1) & 0xffff
#
 
def _idea_crypt(ckey, block, _mul=_idea_mul, _pack=struct.pack, _unpack=struct.unpack):
  if len(block) != 8: raise ValueError('IDEA block size must be 8, got: %d' % len(block))
  a, b, c, d = _unpack('>4H', block)
  for j in range(0, 48, 6):
    a, b, c, d = _mul(a, ckey[j]), (b + ckey[j + 1]) & 0xffff, (c + ckey[j + 2]) & 0xffff, _mul(d, ckey[j + 3])
    t, u = c, b
    c = _mul(a ^ c, ckey[j + 4])
    b = _mul(((b ^ d) + c) & 0xffff, ckey[j + 5])
    c = (c + b) & 0xffff
    a ^= b
    d ^= c
    b ^= t
    c ^= u
  #
  return _pack('>4H', _mul(a, ckey[48]), (c + ckey[49]) & 0xffff, (b + ckey[50]) & 0xffff, _mul(d, ckey[51]))
#
 
class IDEA(object):
  """IDEA block cipher."""
  key_size = 16
  block_size = 8
 
  __slots__ = ('_ckey', '_dkey')

  def __init__(self, key, _inv=_idea_inv):
    if len(key) != 16:
      raise ValueError('IDEA key size must be 16, got: %d' % len(key))
    ckey = [0] * 52
    ckey[:8] = struct.unpack('>8H', key)
    for i in range(0, 44):
      ckey[i + 8] = (ckey[(i & ~7) + ((i + 1) & 7)] << 9 | ckey[(i & ~7) + ((i + 2) & 7)] >> 7) & 0xffff
    print("ckey = " + str(ckey));    
    self._ckey = tuple(ckey)
    dkey = [0] * 52
    dkey[48], dkey[49], dkey[50], dkey[51] = _inv(ckey[0]), 0xffff & -ckey[1], 0xffff & -ckey[2], _inv(ckey[3])
    for i in range(42, -6, -6):
      dkey[i + 4], dkey[i + 5], dkey[i], dkey[i + 3] = ckey[46 - i], ckey[47 - i], _inv(ckey[48 - i]), _inv(ckey[51 - i])
      dkey[i + 1 + (i > 0)], dkey[i + 2 - (i > 0)] = 0xffff & -ckey[49 - i], 0xffff & -ckey[50 - i]
    self._dkey = tuple(dkey)
  #

  def encrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._ckey, block)
  #
 
  def decrypt(self, block, _idea_crypt=_idea_crypt):
    return _idea_crypt(self._dkey, block)
  #
#

del _idea_mul, _idea_inv, _idea_crypt
 
if __name__ == '__main__':
  # Test vectors from: https://www.cosic.esat.kuleuven.be/nessie/testvectors/
  key = '0123456789ABCDEF0123456789ABCDEF'
  key = bytes.fromhex(key) ## data.decode('hex')
  cb = IDEA(key)

  encryptedData = '18d9681415931ef0' ## abc123

  decryptedData = cb.decrypt(bytes.fromhex(encryptedData)).decode('cp437')
  print("decryptedData: [" + decryptedData + "]")

  encryptedData = cb.encrypt(decryptedData.encode("cp437"))
  encryptedData = "".join("{:02x}".format(b) for b in encryptedData)
  print("encryptedData: [" + encryptedData + "]")

  quit()
#
