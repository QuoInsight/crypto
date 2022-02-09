#!/usr/bin/env python

# https://github.com/bozhu/IDEA-Python/blob/master/idea.py
# A Python implementation of the block cipher IDEA
# Copyright (c) 2015 Bo Zhu https://about.bozhu.me
# MIT License

def _mul(x, y):
  if x == 0: x = 0x10000
  if y == 0: y = 0x10000
  r = (x * y) % 0x10001
  if r == 0x10000: r = 0
  return r
#

def _KA_layer(x1, x2, x3, x4, round_keys):
  z1, z2, z3, z4 = round_keys[0:4]
  y1 = _mul(x1, z1)
  y2 = (x2 + z2) % 0x10000
  y3 = (x3 + z3) % 0x10000
  y4 = _mul(x4, z4)
  return y1, y2, y3, y4
#

def _MA_layer(y1, y2, y3, y4, round_keys):
  z5, z6 = round_keys[4:6]
  p = y1 ^ y3
  q = y2 ^ y4
  s = _mul(p, z5)
  t = _mul((q + s) % 0x10000, z6)
  u = (s + t) % 0x10000
  x1 = y1 ^ t
  x2 = y2 ^ u
  x3 = y3 ^ t
  x4 = y4 ^ u

  return x1, x2, x3, x4
#

class IDEA:
  def __init__(self, key):
    self._keys = None
    self.change_key(key)
  #

  def change_key(self, key):
    modulus = 1 << 128
    sub_keys = []
    for i in range(9 * 6):
      sub_keys.append((key >> (112 - 16 * (i % 8))) % 0x10000)
      if i % 8 == 7: key = ((key << 25) | (key >> 103)) % modulus
    #
    keys = []
    for i in range(9):
      round_keys = sub_keys[6 * i: 6 * (i + 1)]
      keys.append(tuple(round_keys))
    self._keys = tuple(keys)
  #

  def encrypt(self, data8bytes):
    x1 = (data8bytes >> 48) & 0xFFFF
    x2 = (data8bytes >> 32) & 0xFFFF
    x3 = (data8bytes >> 16) & 0xFFFF
    x4 = data8bytes & 0xFFFF
    for i in range(8):
      round_keys = self._keys[i]
      y1, y2, y3, y4 = _KA_layer(x1, x2, x3, x4, round_keys)
      x1, x2, x3, x4 = _MA_layer(y1, y2, y3, y4, round_keys)
      x2, x3 = x3, x2
    #
    # Note: The words x2 and x3 are not permuted in the last round
    # So here we use x1, x3, x2, x4 as input instead of x1, x2, x3, x4
    # in order to cancel the last permutation x2, x3 = x3, x2
    y1, y2, y3, y4 = _KA_layer(x1, x3, x2, x4, self._keys[8])
    ciphertext = (y1 << 48) | (y2 << 32) | (y3 << 16) | y4
    return ciphertext
  #
#

def main():
  # key = 0x00000000000000000000000000000000
  # plain  = 0x8000000000000000
  # cipher = 0x8001000180008000

  key = 0x0123456789ABCDEF0123456789ABCDEF
  print('key\t\t', hex(key))

  data = "abc123  "
  print('data\t\t', data)
  data = "".join("{:02x}".format(ord(c)) for c in data)
  print('data\t\t', data)
  data = int('0x'+data, base=16)
  print('data\t\t', hex(data))

  encrypted = IDEA(key).encrypt(data)
  print('ciphertext\t', hex(encrypted))
#

if __name__ == '__main__':
  main()
#
