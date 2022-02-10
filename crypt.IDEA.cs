using System;

namespace myNameSpace {

  public class myMainClass {

    // Additive Inverse.
    // The argument and the result are within the range 0 .. 0xFFFF.
    private static int addInv(int x) {
      return (0x10000 - x) & 0xFFFF;
    }

    // Multiplicative inverse.
    // The argument and the result are within the range 0 .. 0xFFFF.
    // The following condition is met for all values of x: mul(x, mulInv(x)) == 1
    private static int mulInv(int x) {
      if (x <= 1) return x;
      int y = 0x10001;
      int t0 = 1;
      int t1 = 0;
      while (true) {
        t1 += y / x * t0;
        y %= x;
        if (y == 1) {
          return 0x10001 - t1;
        }
        t0 += x / y * t1;
        x %= y;
        if (x == 1) return t0;
      }
    }

    // Inverts decryption/encrytion sub-keys to encrytion/decryption sub-keys.
    private static int[] invertSubKey(int[] key, int rounds) {
      int[] invKey = new int[key.Length];
      int p = 0;
      int i = rounds * 6;
      invKey[i + 0] = mulInv(key[p++]);
      invKey[i + 1] = addInv(key[p++]);
      invKey[i + 2] = addInv(key[p++]);
      invKey[i + 3] = mulInv(key[p++]);
      for (int r = rounds - 1; r >= 0; r--) {
        i = r * 6;
        int m = r > 0 ? 2 : 1;
        int n = r > 0 ? 1 : 2;
        invKey[i + 4] = key[p++];
        invKey[i + 5] = key[p++];
        invKey[i + 0] = mulInv(key[p++]);
        invKey[i + m] = addInv(key[p++]);
        invKey[i + n] = addInv(key[p++]);
        invKey[i + 3] = mulInv(key[p++]);
      }
      return invKey;
    }

    // Addition in the additive group.
    // The arguments and the result are within the range 0 .. 0xFFFF.
    private static int add(int a, int b) {
      return (a + b) & 0xFFFF;
    }

    // Multiplication in the multiplicative group.
    // The arguments and the result are within the range 0 .. 0xFFFF.
    private static int mul(int a, int b) {
      long r = (long)a * b;
      if (r != 0) {
        return (int)(r % 0x10001) & 0xFFFF;
      } else {
        return (1 - a - b) & 0xFFFF;
      }
    }

    public static byte[] cryptIDEA(byte[] userKey, byte[] data, bool decrypt=false) {
      int rounds = 8;

      // Expands a 16-byte user key to the internal encryption sub-keys.
      if (userKey.Length != 16) {
        throw new ArgumentException("Key length must be 128 bit", "key");
      }
      int[] subKey = new int[rounds * 6 + 4];  // int[52]
      for (int i = 0; i < userKey.Length / 2; i++)  { // [0..7]
        subKey[i] = ((userKey[2*i] & 0xFF) << 8) | (userKey[2*i + 1] & 0xFF);
      }
      for (int i = userKey.Length / 2; i < subKey.Length; i++) { // [8..51]
        subKey[i] = ((subKey[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9) | (subKey[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7)) & 0xFFFF;
      }
      if (decrypt) subKey = invertSubKey(subKey, rounds);

      if (data.Length < rounds) {
        byte[] tmpData = new byte[rounds];
        for (int i=0; i<data.Length; i++) {
          tmpData[i] = data[i];
        }
        for (int i=data.Length; i<tmpData.Length; i++) {
          tmpData[i] = 32; // append/pad with some space by default !!
        }
        data = tmpData;
      }

      int x0 = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
      int x1 = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
      int x2 = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
      int x3 = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
      //
      int p = 0;
      for (int round = 0; round < rounds; round++) {
        int y0 = mul(x0, subKey[p++]);
        int y1 = add(x1, subKey[p++]);
        int y2 = add(x2, subKey[p++]);
        int y3 = mul(x3, subKey[p++]);
        //
        int t0 = mul(y0 ^ y2, subKey[p++]);
        int t1 = add(y1 ^ y3, t0);
        int t2 = mul(t1, subKey[p++]);
        int t3 = add(t0, t2);
        //
        x0 = y0 ^ t2;
        x1 = y2 ^ t2;
        x2 = y1 ^ t3;
        x3 = y3 ^ t3;
      }
      //
      int r0 = mul(x0, subKey[p++]);
      int r1 = add(x2, subKey[p++]);
      int r2 = add(x1, subKey[p++]);
      int r3 = mul(x3, subKey[p++]);
      //
      data[0] = (byte)(r0 >> 8);
      data[1] = (byte)r0;
      data[2] = (byte)(r1 >> 8);
      data[3] = (byte)r1;
      data[4] = (byte)(r2 >> 8);
      data[5] = (byte)r2;
      data[6] = (byte)(r3 >> 8);
      data[7] = (byte)r3;
      return data;
    }

    public static byte[] HexStr2ByteArr(string hexString) {
      byte[] byteArr = new byte[(int)(hexString.Length/2)];
      for (int i=0; i<byteArr.Length; i++) {
        byteArr[i] = (byte)System.Convert.ToInt32(hexString.Substring(i*2,2), 16);
      }
      return byteArr;
    }

    public static string ByteArr2HexStr(byte[] ba) {
      System.Text.StringBuilder hex = new System.Text.StringBuilder(ba.Length * 2);
      foreach (byte b in ba) hex.AppendFormat("{0:x2}", b);
      return hex.ToString();
    }

    public static void Main(string[] args) {

      Console.WriteLine("\n");
      //Console.Error.WriteLine("OK");

      string strData = "0123456789ABCDEF0123456789ABCDEF";
      byte[] data = new byte[] {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
      };

      data = HexStr2ByteArr(strData);
      strData = ByteArr2HexStr(data);

      byte[] charKey = HexStr2ByteArr("0123456789ABCDEF0123456789ABCDEF");
      strData = "abc123";
      data = System.Text.Encoding.ASCII.GetBytes(strData.PadRight(8));

      data = cryptIDEA(charKey, data); // encrypt
      strData = ByteArr2HexStr(data);
      Console.WriteLine(strData);

      data = cryptIDEA(charKey, data, true); // decrypt
      strData = strData = System.Text.Encoding.ASCII.GetString(data, 0, data.Length);
      Console.WriteLine("[" + strData + "]");

    }

  }
}

